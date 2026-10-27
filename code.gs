// ============================================
// NammaExam Backend — Code.gs
// Deploy as Web App: Execute as Me, Anyone can access
// ============================================

var SS = SpreadsheetApp.getActiveSpreadsheet();
var PROPS = PropertiesService.getScriptProperties();
var CACHE = CacheService.getScriptCache();

// ============================================
// CONFIG
// ============================================
var CONFIG = {
  IMAGE_BASE_URL: 'https://images.nammaexam.com/images/',
  SITE_URL: 'https://nammaexam.com',
  TOKEN_EXPIRY_DAYS: 7,
  MAX_DEVICES: 2,
  SECRET: 'NAMMAEXAM_SECRET_2024',
  RAZORPAY_KEY_ID: '',     // Add your Razorpay key
  RAZORPAY_SECRET: '',      // Add your Razorpay secret
  ADMIN_PASSWORD: 'nammaexam2024'
};

// ============================================
// ROUTING — doGet & doPost
// ============================================
function doGet(e) {
  var action = e.parameter.action;
  
  try {
    switch(action) {
      case 'getExams': return jsonResponse(getExams());
      case 'getPlans': return jsonResponse(getPlans());
      case 'getDashboard': return authRequired(e, getDashboard);
      case 'getQuestions': return authRequired(e, getQuestions);
      case 'getResult': return authRequired(e, getResult);
      case 'getProgress': return authRequired(e, getProgress);
      case 'getLeaderboard': return jsonResponse(getLeaderboard(e));
      case 'adminStats': return adminRequired(e, getAdminStats);
      default: return jsonResponse({error: 'Invalid action', code: 400});
    }
  } catch(err) {
    logError(err, 'doGet', action);
    return jsonResponse({error: 'Server error', code: 500});
  }
}

function doPost(e) {
  var data;
  try {
    data = JSON.parse(e.postData.contents);
  } catch(err) {
    return jsonResponse({error: 'Invalid request body', code: 400});
  }
  
  var action = data.action;
  
  try {
    switch(action) {
      case 'register': return jsonResponse(register!registerUser(data));
      case 'login': return jsonResponse(loginUser(data));
      case 'forgotPassword': return jsonResponse(forgotPassword(data));
      case 'resetPassword': return jsonResponse(resetPassword(data));
      case 'submitResult': return authRequiredPost(data, submitResult);
      case 'createOrder': return authRequiredPost(data, createRazorpayOrder);
      case 'verifyPayment': return authRequiredPost(data, verifyRazorpayPayment);
      default: return jsonResponse({error: 'Invalid action', code: 400});
    }
  } catch(err) {
    logError(err, 'doPost', action);
    return jsonResponse({error: 'Server error', code: 500});
  }
}

// ============================================
// AUTH MIDDLEWARE
// ============================================
function authRequired(e, callback) {
  var token = e.parameter.token;
  var userId = verifyToken(token);
  if (!userId) return jsonResponse({error: 'Unauthorized', code: 401});
  
  // Rate limiting
  if (!checkRateLimit(userId, 'api')) {
    return jsonResponse({error: 'Too many requests', code: 429});
  }
  
  return jsonResponse(callback(userId, e.parameter));
}

function authRequiredPost(data, callback) {
  var token = data.token;
  var userId = verifyToken(token);
  if (!userId) return jsonResponse({error: 'Unauthorized', code: 401});
  
  if (!checkRateLimit(userId, 'api')) {
    return jsonResponse({error: 'Too many requests', code: 429});
  }
  
  return jsonResponse(callback(userId, data));
}

function adminRequired(e, callback) {
  var secret = e.parameter.secret;
  if (secret !== CONFIG.ADMIN_PASSWORD) {
    return jsonResponse({0({error: 'Unauthorized', code: 401});
  }
  return jsonResponse(callback());
}

// ============================================
// TOKEN SYSTEM
// ============================================
function generateToken(userId) {
  var timestamp = Date.now().toString();
  var random = Utilities.getUuid().substring(0, 8);
  var raw = userId + ':' + timestamp + ':' + random;
  var hash = sha256(raw + CONFIG.SECRET);
  return raw + ':' + hash.substring(0, 16);
}

function verifyToken(token) {
  if (!token) return null;
  var parts = token.split(':');
  if (parts.length < 4) return null;
  
  var userId = parts[0];
  var timestamp = parseInt(parts[1]);
  
  // Check expiry
  var expiryMs = CONFIG.TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 1000;
  if (Date.now() - timestamp > expiryMs) return null;
  
  // Verify hash
  var raw = parts[0] + ':' + parts[1] + ':' + parts[2];
  var hash = sha256(raw + CONFIG.SECRET);
  if (hash.substring(0, 16) === parts[3]) {
    return userId;
  }
  return null;
}

// ============================================
// PASSWORD HASHING (SHA-256 + salt)
// ============================================
function hashPassword(password, salt) {
  if (!salt) {
    salt = Utilities.getUuid().substring(0, 16);
  }
  var input = salt + password + salt;
  var hash = sha256(input);
  return salt + ':' + hash;
}

function verifyPassword(password, storedHash) {
  var parts = storedHash.split(':');
  var salt = parts[0];
  var newHash = hashPassword(password, salt);
  return newHash === storedHash;
}

function sha256(input) {
  var digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, input);
  var hash = '';
  for (var i = 0; i < digest.length; i++) {
    hash += ('0' + (digest[i] & 0xFF).toString(16)).slice(-2);
  }
  return hash;
}

// ============================================
// INPUT SANITIZATION
// ============================================
function sanitize(str) {
  if (!str) return '';
  return str.toString().trim()
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ============================================
// RATE LIMITING
// ============================================
function checkRateLimit(userId, action) {
  var key = 'rate_' + userId + '_' + action;
  var count = parseInt(CACHE.get(key) || '0');
  var limits = {
    'api': 60,        // 60 API calls per 10 min
    'login': 5,       // 5 login attempts per 10 min
    'register': 3,    // 3 register attempts per 10 min
    'submit': 10       // 10 submissions per 10 min
  };
  var limit = limits[action] || 60;
  if (count >= limit) return false;
  CACHE.put(key, (count + 1).toString(), 600); // 10 minutes
  return true;
}

// ============================================
// REGISTER
// ============================================
function registerUser(data) {
  // Validate
  if (!data.name || !data.email || !data.password) {
    return {success: false, error: 'Missing required fields'};
  }
  
  var name = sanitize(data.name);
  var email = sanitize(data.email).toLowerCase();
  var phone = sanitize(data.phone || '');
  var password = data.password;
  
  if (password.length < 6) {
    return {success: false, error: 'Password too short (min 6 characters)'};
  }
  
  if (!email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
    return {success: false, error: 'Invalid email format'};
  }
  
  // Check if email exists
  var sheet = SS.getSheetByName('users');
  var userData = sheet.getDataRange().getValues();
  
  for (var i = 1; i < userData.length; i++) {
    if (userData[i][1] === email) {
      return {success: false, error: 'This email is already registered'};
    }
  }
  
  // Rate limit
  if (!checkRateLimit(email, 'register')) {
    return {success: false, error: 'Too many attempts. Try again later.'};
  }
  
  // Create user
  var userId = 'U-' + (userData.length).toString().padStart(4, '0');
  var passwordHash = hashPassword(password);
  var now = new Date().toISOString();
  
  sheet.appendRow([
    userId,
    email,
    passwordHash,
    name,
    phone,
    now,      // created_at
    now,      // last_login
    false,    // email_verified
    '',       // reset_token
    '',       // reset_expires
    'active'  // status
  ]);
  
  // Generate token
  var token = generateToken(userId);
  
  // Send welcome email
  try {
    MailApp.sendEmail({
      to: email,
      subject: 'Welcome to NammaExam! 🔥',
      htmlBody: 
        '<h2>Welcome, ' + name + '!</h2>' +
        '<p>Your account is ready. Start practicing for free:</p>' +
        '<p><a href="' + CONFIG.SITE_URL + '/dashboard" style="background:#d62828;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none">Go to Dashboard</a></p>' +
        '<p>— Team NammaExam</p>'
    });
  } catch(e) {}
  
  return {
    success: true,
    token: token,
    user: {
      userId: userId,
      name: name,
      email: email,
      plan: 'free'
    }
  };
}

// ============================================
// LOGIN
// ============================================
function loginUser(data) {
  if (!data.email || !data.password) {
    return {success: false, error: 'Missing email or password'};
  }
  
  var email = data.email.toLowerCase().trim();
  
  // Rate limit
  if (!checkRateLimit(email, 'login')) {
    return {success: false, error: 'Too many attempts. Try again in 10 minutes.'};
  }
  
  var sheet = SS.getSheetByName('users');
  var userData = sheet.getDataRange().getValues();
  
  for (var i = 1; i < userData.length; i++) {
    if (userData[i][1] === email) {
      if (verifyPassword(data.password, userData[i][2])) {
        // Update last login
        sheet.getRange(i + 1, 7).setValue(new Date().toISOString());
        
        var userId = userData[i][0];
        var token = generateToken(userId);
        var plan = getUserPlan(userId);
        
        return {
          success: true,
          token: token,
          user: {
            userId: userId,
            name: userData[i][3],
            email: userData[i][1],
            plan: plan.plan,
!            unlockedExams: plan.unlockedExams
          }
        };
      } else {
        return {success: false, error: 'Wrong password'};
      }
    }
  }
  
  return {success: false, error: 'Email not found'};
}

// ============================================
// FORGOT PASSWORD
// ============================================
function forgotPassword(data) {
  if (!data.email) return {success: false, error: 'Email required'};
  
  var email = data.email.toLowerCase().trim();
  var sheet = SS.getSheetByName('users');
  var userData = sheet.getDataRange().getValues();
  
  for (var i = 1; i < userData.length; i++) {
    if (userData[i][1] === email) {
      // Generate reset token
      var resetToken = 'reset_' + Utilities.getUuid().substring(0, 12);
      var expiresAt = new Date(Date.now() + 3600000).toISOString(); // 1 hour
      
      // Save to sheet
      sheet.getRange(i + 1, 9).setValue(resetToken);
      sheet.getRange(i + 1, 10).setValue(expiresAt);
      
      // Send email
      try {
        MailApp.sendEmail({
          to: email,
          subject: 'Reset Your NammaExam Password',
          htmlBody: 
            '<h2>Password Reset</h2>' +
            '<p>Click below to reset your password:</p>' +
            '<p><a href="' + CONFIG.SITE_URL + '/reset-password.html?t=' + resetToken + '" style="background:#d62828;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none">Reset Password</a></p>' +
            '<p>This link expires in 1 hour.</p>'
        });
      } catch(e) {}
      
      return {success: true, message: 'Reset link sent to your email'};
    }
  }
  
  return {success: false, error: 'Email not found'};
}

function resetPassword(data) {
  if (!data.token || !data.newPassword) {
    return {success: false, error: 'Missing fields'};
  }
  
  var sheet = SS.getSheetByName('users');
  var userData = sheet.getDataRange().getValues();
  
  for (var i = 1; i < userData.length; i++) {
    if (userData[i][8] === data.token) {
      var expires = new Date(userData[i][9]);
      if (new Date() > expires) {
        return {success: false, error: 'Reset link expired'};
      }
      
      // Update password
      var newHash = hashPassword(data.newPassword);
      sheet.getRange(i + 1, 3).setValue(newHash);
      sheet.getRange(i + 1, 9).setValue(''); // Clear token
      sheet.getRange(i + 1, 10).setValue('');
      
      return {success: true, message: 'Password updated'};
    }
  }
  
  return {success: false, error: 'Invalid reset token'};
}

// ============================================
// GET USER PLAN
// ============================================
function getUserPlan(userId) {
  var sheet = SS.getSheetByName('user_plans');
  if (!sheet) return {plan: 'free', unlockedExams: []};
  
  var data = sheet.getDataRange().getValues();
  var plan = 'free';
  var unlockedExams = [];
  
  for (var i = 1; i < data.length; i++) {
    if (data[i][0] === userId && data[i][4] === 'active') {
      plan = data[i][1];
      
      // Check expiry
      var expires = data[i][3] ? new Date(data[i][3]) : null;
      if (expires && new Date() > expires) {
        plan = 'free';
        continue;
      }
      
      // Get unlocked exams
      var planSheet = SS.getSheetByName('plans');
      if (planSheet) {
        var planData = planSheet.getDataRange().getValues();
        for (var j = 1; j < planData.length; j++) {
          if (planData[j][0] === plan) {
            unlockedExams = (planData[j][2] || '').split(',').filter(function(e){return e});
          }
        }
      }
      break;
    }
  }
  
  return {plan: plan, unlockedExams: unlockedExams};
}

// ============================================
// GET EXAMS
// ============================================
function getExams() {
  var cacheKey = 'exams_list';
  var cached = CACHE.get(cacheKey);
  if (cached) return JSON.parse(cached);
  
  var sheet = SS.getSheetByName('exams');
  if (!sheet) return {exams: []};
  
  var data = sheet.getDataRange().getValues();
  var headers = data[0];
  var exams = [];
  
  for (var i = 1; i < data.length; i++) {
    if (data[i][10] === 'active') { // status column
      exams.push({
        examId: data[i][0],
        examName: data[i][1],
        body: data[i][2],
        totalQs: data[i][4],
        duration: data[i][5],
        sections: data[i][6],
        hasNegative: data[i][7],
        negativeMark: data[i][8],
        freePaper: data[i][9]
      });
    }
  }
  
  var result = {exams: exams};
  CACHE.put(cacheKey, JSON.stringify(result), 21600); // 6 hours
  return result;
}

// ============================================
// GET PLANS
// ============================================
function getPlans() {
  var sheet = SS.getSheetByName('plans');
  if (!sheet) return {plans: []};
  
  var data = sheet.getDataRange().getValues();
  var plans = [];
  
  for (var i = 1; i < data.length; i++) {
    plans.push({
      planId: data[i][0],
      planName: data[i][1],
      price: data[i][2],
      examIds: (data[i][3] || '').split(',').filter(function(e){return e}),
      papersPerExam: data[i][4],
      sectionalsPerExam: data[i][5],
      mocksPerExam: data[i][6],
      description: data[i][7],
      isPopular: data[i][8] === true
    });
  }
  
  return {plans: plans};
}

// ============================================
// GET DASHBOARD
// ============================================
function getDashboard(userId, params) {
  var results = getUserResults(userId);
  var stats = calculateStats(results);
  var recentResults = results.slice(0, 5).map(function(r) {
    return {
      resultId: r.resultId,
      examId: r.examId,
      examName: getExamName(r.examId),
      paperId: r.paperId,
      score: r.score,
      total: r.total,
      accuracy: r.accuracy,
      timeTaken: r.timeTaken,
      submittedAt: r.submittedAt
    };
  });
  
  // Section performance
  var sectionPerf = calculateSectionPerformance(results);
  
  // Topic accuracy
  var topicAcc = calculateTopicAccuracy(userId);
  
  return {
    stats: stats,
    recentResults: recentResults,
    sectionPerformance: sectionPerf,
    topicAccuracy: topicAcc
  };
}

function getUserResults(userId) {
  var sheet = SS.getSheetByName('results');
  if (!sheet) return [];
  
  var data = sheet.getDataRange().getValues();
  var results = [];
  
  for (var i = 1; i < data.length; i++) {
    if (data[i][1] === userId) {
      results.push({
        resultId: data[i][0],
        examId: data[i][2],
        paperId: data[i][3],
        score: data[i][4],
        total: data[i][5],
        accuracy: data[i][6],
        timeTaken: data[i][8],
        submittedAt: data[i][25] || data[i][20] || ''
      });
    }
  }
  
  // Sort by date descending
  results.sort(function(a, b) {
    return new Date(b.submittedAt) - new Date(a.submittedAt);
  });
  
  return results;
}

function calculateStats(results) {
  if (results.length === 0) {
    return {
      testsTaken: 0,
      avgAccuracy: 0,
      bestScore: 0,
      streak: 0,
      totalTime: '0h',
      newUsersToday: 0,
      testsToday: 0
    };
  }
  
  var totalAccuracy = 0;
  var bestScore = 0;
  
  results.forEach(function(r) {
    totalAccuracy += (r.accuracy || 0);
    if (r.score > bestScore) bestScore = r.score;
  });
  
  return {
    testsTaken: results.length,
    avgAccuracy: Math.round(totalAccuracy / results.length),
    bestScore: bestScore,
    streak: calculateStreak(results),
    totalTime: calculateTotalTime(results)
  };
}

function calculateStreak(results) {
  if (results.length === 0) return 0;
  
  var today = new Date();
  today.setHours(0, 0, 0, 0);
  var streak = 0;
  var checkDate = new Date(today);
  
  for (var d = 0; d < 30; d++) {
    var dayStr = checkDate.toISOString().split('T')[0];
    var found = false;
    
    for (var i = 0; i < results.length; i++) {
      var rDate = (results[i].submittedAt || '').split('T')[0];
      if (rDate === dayStr) {
        found = true;
        break;
      }
    }
    
    if (found) {
      streak++;
    } else if (d > 0) {
      break;
    }
    
    checkDate.setDate(checkDate.getDate() - 1);
  }
  
  return streak;
}

function calculateTotalTime(results) {
  var totalMin = 0;
  results.forEach(function(r) {
    var parts = (r.timeTaken || '0:0').split(':');
    totalMin += parseInt(parts[0]) * 60 + parseInt(parts[1] || 0);
  });
  
  var hours = Math.floor(totalMin / 60);
  var mins = totalMin % 60;
  return hours + 'h ' + mins + 'm';
}

function calculateSectionPerformance(results) {
  var sections = {};
  
  results.forEach(function(r) {
    // This uses the section columns from results sheet
    // Based on your sheet structure
    var sectionNames = ['Reasoning', 'GA', 'Quant', 'English'];
    var sectionScores = [r.section1_score, r.section2_score, r.section3_score, r.section4_score];
    var sectionTotals = [r.section1_total, r.section2_total, r.section3_total, r.section4_total];
    
    for (var i = 0; i < sectionNames.length; i++) {
      if (sectionScores[i] !== undefined && sectionTotals[i] > 0) {
        if (!sections[sectionNames[i]]) {
          sections[sectionNames[i]] = {correct: 0, total: 0};
        }
        sections[sectionNames[i]].correct += sectionScores[i];
        sections[sectionNames[i]].total += sectionTotals[i];
      }
    }
  });
  
  var result = {};
  Object.keys(sections).forEach(function(sec) {
    result[sec] = Math.round(sections[sec].correct / sections[sec].total * 100);
  });
  
  return result;
}

function calculateTopicAccuracy(userId) {
  var sheet = SS.getSheetByName('answers_detail');
  if (!sheet) return {};
  
  var data = sheet.getDataRange().getValues();
  var topics = {};
  
  for (var i = 1; i < data.length; i++) {
    if (data[i][0] !== userId && data[i][1] !== userId) continue;
    
    var topic = data[i][7] || 'Unknown'; // topic column
    var isCorrect = data[i][4] === true;
    
    if (!topics[topic]) {
      topics[topic] = {correct: 0, total: 0};
    }
    topics[topic].total++;
    if (isCorrect) topics[topic].correct++;
  }
  
  var result = {};
  Object.keys(topics).forEach(function(t) {
    result[t] = Math.round(topics[t].correct / topics[t].total * 100);
  });
  
  return result;
}

function getExamName(examId) {
  var exams = getExams().exams;
  for (var i = 0; i < exams.length; i++) {
    if (exams[i].examId === examId) return exams[i].examName;
  }
  return examId;
}

// ============================================
// GET QUESTIONS (with caching, bilingual, hide answers)
// ============================================
function getQuestions(userId, params) {
  var examId = params.examId;
  var paperId = params.paperId;
  
  if (!examId || !paperId) {
    return {error: 'Missing examId or paperId'};
  }
  
  // Check access
  var hasAccess = checkAccess(userId, examId, paperId);
  if (!hasAccess.allowed) {
    return {error: 'Access denied', code: 403, reason: hasAccess.reason};
  }
  
  // Check cache
  var cacheKey = 'qs_' + examId + '_' + paperId;
  var cached = CACHE.get(cacheKey);
  
  if (cached) {
    var cachedData = JSON.parse(cached);
    // Remove correct answers before sending
    return removeCorrectAnswers(cachedData);
  }
  
  // Get sheet name for this exam
  var sheetName = getQuestionSheetName(examId);
  if (!sheetName) return {error: 'Exam not found'};
  
  var sheet = SS.getSheetByName(sheetName);
  if (!sheet) return {error: 'Questions not available'};
  
  var data = sheet.getDataRange().getValues();
  var headers = data[0];
  var questions = [];
  
  // Find column indices
  var colMap = {};
  headers.forEach(function(h, idx) {
    colMap[h] = idx;
  });
  
  for (var i = 1; i < data.length; i++) {
    // Match exam_id and paper_id
    var rowExamId = data[i][colMap['exam_id'] || 1] || '';
    var rowPaperType = data[i][colMap['paper_type'] || 2] || '';
    var rowYear = data[i][colMap['year'] || 3] || '';
    var rowPaperId = rowExamId + '-' + rowPaperType + '-' + rowYear;
    
    if (rowExamId !== examId) continue;
    if (rowPaperId !== paperId) continue;
    
    questions.push({
      id: data[i][colMap['q_id'] || 0],
      exam_id: rowExamId,
      paper_type: rowPaperType,
      year: rowYear,
      section: data[i][colMap['section'] || 4],
      topic: data[i][colMap['topic'] || 5],
      q_num: data[i][colMap['q_num'] || 6],
      question_en: data[i][colMap['question_en'] || 7] || '',
      question_hi: data[i][colMap['question_hi'] || 8] || '',
      opt_a_en: data[i][colMap['opt_a_en'] || 9] || '',
      opt_a_hi: data[i][colMap['opt_a_hi'] || 10] || '',
      opt_b_en: data[i][colMap['opt_b_en'] || 11] || '',
      opt_b_hi: data[i][colMap['opt_b_hi'] || 12] || '',
      opt_c_en: data[i][colMap['opt_c_en'] || 13] || '',
      opt_c_hi: data[i][colMap['opt_c_hi'] || 14] || '',
      opt_d_en: data[i][colMap['opt_d_en'] || 15] || '',
      opt_d_hi: data[i][colMap['opt_d_hi'] || 16] || '',
      correct: data[i][colMap['correct'] || 13],
      image_type: data[i][colMap['image_type'] || 14] || 'none',
      image_url: data[i][colMap['image_url'] || 15] || '',
      difficulty: data[i][colMap['difficulty'] || 16] || 'medium'
    });
  }
  
  // Sort by q_num
  questions.sort(function(a, b) {
    return (a.q_num || 0) - (b.q_num || 0);
  });
  
  var result = {
    questions: questions,
    totalQuestions: questions.length,
    duration: questions.length > 0 ? Math.ceil(questions.length / 100 * 60) : 60
  };
  
  // Cache for 6 hours
  CACHE.put(cacheKey, JSON.stringify(result), 21600);
  
  // Return without correct answers
  return removeCorrectAnswers(result);
}

function removeCorrectAnswers(data) {
  var clone = JSON.parse(JSON.stringify(data));
  if (clone.questions) {
    clone.questions.forEach(function(q) {
      delete q.correct;
    });
  }
  return clone;
}

function getQuestionSheetName(examId) {
  if (examId.startsWith('ssc-')) return 'ssc_questions';
  if (examId.startsWith('upsc-')) return 'upsc_questions';
  if (examId.startsWith('rrb-')) return 'rrb_questions';
  if (examId.startsWith('ibps-') || examId.startsWith('sbi-') || 
      examId.startsWith('rbi-') ||5   examId.startsWith('lic-') ||
      examId.startsWith('nabard-') || examId.startsWith('sebi-')) return 'bank_questions';
  if (examId.startsWith('afcat') || examId.startsWith('inet')) return 'defence_questions';
  return null;
}

function checkAccess(userId, examId, paperId) {
  var plan = getUserPlan(userId);
  var planId = plan.plan;
  var unlockedExams = plan.unlockedExams;
  
  // Full access
  if (planId === 'full' || planId === 'full-access') {
    return {allowed: true};
  }
  
  // Check pack access
  if (unlockedExams.indexOf('ALL') !== -1) return {allowed: true};
  if (unlockedExams.indexOf(examId) !== -1) return {allowed: true};
  
  // Check if this is a free paper
  var examsData = getExams().exams;
  for (var i = 0; i < examsData.length; i++) {
    if (examsData[i].examId === examId) {
      var freePaper = examsData[i].freePaper;
      if (paperId.indexOf(freePaper) !== -1) {
        return {allowed: true, isFree: true};
      }
    }
  }
  
  return {allowed: false, reason: 'Plan required'};
}

// ============================================
// SUBMIT RESULT
// ============================================
function submitResult(userId, data) {
  // Use lock to prevent concurrent write issues
  var lock = LockService.getScriptLock();
  var success = lock.tryLock(30000);
  if (!success) {
    return {error: 'Server busy, please try again'};
  }
  
  try {
    var answers = data.answers || [];
    var examId = data.examId;
    var paperId = data.paperId;
    var totalQuestions = data.totalQuestions || answers.length;
    var timeTaken = data.timeTaken || '0:00';
    
    // Get correct answers from sheet
    var sheetName = getQuestionSheetName(examId);
    var qSheet = SS.getSheetByName(sheetName);
    var correctAnswers = {};
    
    if (qSheet) {
      var qData = qSheet.getDataRange().getValues();
      var headers = qData[0];
      var colMap = {};
      headers.forEach(function(h, idx) { colMap[h] = idx; });
      
      for (var i = 1; i < qData.length; i++) {
        var qId = qData[i][colMap['q_id'] || 0];
        var correct = qData[i][colMap['correct'] || 13];
        var section = qData[i][colMap['section'] || 4];
        var topic = qData[i][colMap['topic'] || 5];
        if (qId) {
          correctAnswers[qId] = {
            correct: correct,
            section: section,
            topic: topic
          };
        }
      }
    }
    
    // Calculate score
    var score = 0;
    var sectionScores = {};
    var sectionTotals = {};
    var totalNegMarks = 0;
    var negMark = 0.25; // default
    var hasNegative = true;
    
    // Check exam for negative marking
    var examsData = getExams().exams;
    for (var e = 0; e < examsData.length; e++) {
      if (examsData[e].examId === examId) {
        hasNegative = examsData[e].hasNegative;
        negMark = parseFloat(examsData[e].negativeMark) || 0.25;
      }
    }
    
    // Process answers
    var answerDetails = [];
    
    answers.forEach(function(ans) {
      var qId = ans.qId || ans.q_id || ans.qIndex;
      var yourAnswer = ans.yourAnswer || null;
      var correctInfo = correctAnswers[qId] || {};
      var correctAnswer = correctInfo.correct || ans.correctAnswer;
      var section = ans.section || correctInfo.section || 'Unknown';
      var topic = ans.topic || correctInfo.topic || '';
      
      var isCorrect = yourAnswer && yourAnswer === correctAnswer;
      var isSkipped = !yourAnswer || yourAnswer === 'null';
      
      if (isCorrect) {
        score++;
      } else if (!isSkipped && hasNegative) {
        totalNegMarks += negMark;
      }
      
      // Section tracking
      if (!sectionScores[section]) {
        sectionScores[section] = 0;
        sectionTotals[section] = 0;
      }
      sectionTotals[section]++;
      if (isCorrect) sectionScores[section]++;
      
      // Detail for answers_detail sheet
      answerDetails.push({
        qId: qId,
        yourAnswer: yourAnswer,
        correctAnswer: correctAnswer,
        isCorrect: isCorrect,
        isSkipped: isSkipped,
        section: section,
        topic: topic
      });
    });
    
    var finalScore = Math.max(0, score - totalNegMarks);
    var accuracy = Math.round(score / totalQuestions * 100);
    
    // Generate result ID
    var resultId = 'RES-' + Date.now();
    
    // Count attempt number
    var existingResults = getUserResults(userId);
    var attemptNum = 1;
    existingResults.forEach(function(r) {
      if (r.examId === examId && r.paperId === paperId) {
        attemptNum++;
      }
    });
    
    // Section names for sheet columns
    var sectionNames = Object.keys(sectionScores);
    var s1 = sectionNames[0] || '';
    var s2 = sectionNames[1] || '';
    var s3 = sectionNames[2] || '';
    var s4 = sectionNames[3] || '';
    var s5 = sectionNames[4] || '';
    
    // Save to results sheet
    var rSheet = SS.getSheetByName('results');
    rSheet.appendRow([
      resultId,                    // result_id
      userId,                     // user_id=       examId,                    // exam_id
      paperId,                    // paper_id
      score,                      // score (correct count)
      totalQuestions,             // total
      accuracy,                   // accuracy
      totalNegMarks.toFixed(2),   // negative_marks
      finalScore.toFixed(2),      // final_score
      timeTaken,                  // time_taken
      s1,                         // section1_name
      sectionScores[s1] || 0,    // section1_score
      sectionTotals[s1] || 0,    // section1_total
      s2,                         // section2_name
      sectionScores[s2] || 0,    // section2_score
      sectionTotals[s2] || 0,    // section2_total
      s3,                         // section3_name
      sectionScores[s3] || 0,    // section3_score
      sectionTotals[s3] || 0,    // section3_total
      s4,                         // section4_name
      sectionScores[s4] || 0,    // section4_score
      sectionTotals[s4] || 0,    // section4_total
      s5,                         // section5_name
      sectionScores[s5] || 0,    // section5_score
      sectionTotals[s5] || 0,    // section5_total
      new Date().toISOString(),  // submitted_at
      attemptNum                  // attempt_num
    ]);
    
    // Save detailed answers
    var aSheet = SS.getSheetByName('answers_detail');
    answerDetails.forEach(function(detail) {
      aSheet.appendRow([
        resultId,                   // result_id
        userId,                    // user_id (also in column B for some queries)
        detail.qId,                // q_id
        detail.yourAnswer,         // your_answer
        detail.correctAnswer,      // correct_answer
        detail.isCorrect,         // is_correct
        detail.isSkipped,         // is_skipped
        detail.section,           // section
        detail.topic              // topic
      ]);
    });
    
    return {
      success: true,
      resultId: resultId,
      score: score,
      total: totalQuestions,
      accuracy: accuracy,
      finalScore: finalScore.toFixed(2),
      negativeMarks: totalNegMarks.toFixed(2),
      sectionScores: sectionScores,
      sectionTotals: sectionTotals
    };
    
  } finally {
    lock.releaseLock();
  }
}

// ============================================
// GET RESULT
// ============================================
function getResult(userId, params) {
  var resultId = params.resultId;
  if (!resultId) return {error: 'Missing resultId'};
  
  var sheet = SS.getSheetByName('results');
  var data = sheet.getDataRange().getValues();
  
  for (var i = 1; i < data.length; i++) {
    if (data[i][0] === resultId && data[i][1] === userId) {
      var result = {
        resultId: data[i][0],
        examId: data[i][2],
        paperId: data[i][3],
        score: data[i][4],
        total: data[i][5],
        accuracy: data[i][6],
        negativeMarks: data[i][7],
        finalScore: data[i][8],
        timeTaken: data[i][9],
        section1_name: data[i][10],
        section1_score: data[i][11],
        section1_total: data[i][12],
        section2_name: data[i][13],
        section2_score: data[i][14],
        section2_total: data[i][15],
        section3_name: data[i][16],
        section3_score: data[i][17],
        section3_total: data[i][18],
        section4_name: data[i][19],
        section4_score: data[i][20],
        section4_total: data[i][21],
        section5_name: data[i][22],
        section5_score: data[i][23],
        section5_total: data[i][24],
        submittedAt: data[i][25]
      };
      
      // Get detailed answers
      var answers = getDetailedAnswers(resultId);
      
      return {
        result: result,
        answers: answers
      };
    }
  }
  
  return {error: 'Result not found'};
}

function getDetailedAnswers(resultId) {
  var sheet = SS.getSheetByName('answers_detail');
  if (!sheet) return [];
  
  var data = sheet.getDataRange().getValues();
  var answers = [];
  
  for (var i = 1; i < data.length; i++) {
    if (data[i][0] === resultId) {
      answers.push({
        qId: data[i][2],
        yourAnswer: data[i][3],
        correctAnswer: data[i][4],
        isCorrect: data[i][5] === true,
        isSkipped: data[i][6] === true,
        section: data[i][7],
        topic: data[i][8]
      });
    }
  }
  
  return answers;
}

// ============================================
// GET PROGRESS
// ============================================
function getProgress(userId, params) {
  var results = getUserResults(userId);
  var stats = calculateStats(results);
  var sectionPerf = calculateSectionPerformance(results);
  var topicAcc = calculateTopicAccuracy(userId);
  
  return {
    stats: stats,
    sectionPerformance: sectionPerf,
    topicAccuracy: topicAcc,
    recentResults: results.slice(0, 20)
  };
}

// ============================================
// LEADERBOARD
// ============================================
function getLeaderboard(params) {
  var examId = params.examId;
  var paperId = params.paperId;
  
  var sheet = SS.getSheetByName('results');
  var data = sheet.getDataRange().getValues();
  var entries = [];
  
  for (var i = 1; i < data.length; i++) {
    if (data[i][2] === examId && data[i][3] === paperId) {
      entries.push({
        userId: data[i][1],
        score: data[i][4],
        accuracy: data[i][6],
        timeTaken: data[i][9]
      });
    }
  }
  
  entries.sort(function(a, b) { return b.score - a.score; });
  
  return {
    leaderboard: entries.slice(0, 50)
  };
}

// ============================================
// RAZORPAY — Create Order
// ============================================
function createRazorpayOrder(userId, data) {
  var planId = data.planId;
  var amount = data.amount;
  
  if (!planId || !amount) {
    return {error: 'Missing plan or amount'};
  }
  
  // Verify amount matches plan price
  var planSheet = SS.getSheetByName('plans');
  var planData = planSheet.getDataRange().getValues();
  var validAmount = false;
  
  for (var i = 1; i < planData.length; i++) {
    if (planData[i][0] === planId && planData[i][2] === amount) {
      validAmount = true;
    }
  }
  
  if (!validAmount) {
    return {error: 'Invalid amount'};
  }
  
  // Create Razorpay order
  var orderId = 'order_' + Date.now();
  var razorpayOrderId = '';
  
  if (CONFIG.RAZORPAY_KEY_ID && CONFIG.RAZORPAY_SECRET) {
    try {
      var payload = {
        amount: amount * 100, // paise
        currency: 'INR',
        receipt: 'rcpt_' + userId + '_' + planId,
        notes: {
          userId: userId,
          planId: planId
        }
      };
      
      var authHeader = 'Basic ' + Utilities.base64Encode(
        CONFIG.RAZORPAY_KEY_ID + ':' + CONFIG.RAZORPAY_SECRET
      );
      
      var response = UrlFetchApp.fetch('https://api.razorpay.com/v1/orders', {
        method: 'post',
        headers: {
          'Authorization': authHeader,
          'Content-Type': 'application/json'
        },
        payload: JSON.stringify(payload)
      });
      
      var orderData = JSON.parse(response.getContentText());
      razorpayOrderId = orderData.id;
    } catch(e) {
      logError(e, 'createRazorpayOrder', userId);
      return {error: 'Payment service error'};
    }
  }
  
  // Save payment record
  var paymentId = 'PAY-' + Date.now();
  var pSheet = SS.getSheetByName('payments');
  pSheet.appendRow([
    paymentId,
    userId,
    planId,
    amount,
    razorpayOrderId,
    '',                    // razorpay_payment_id (filled on verify)
    'created',
7    new Date().toISOString()
  ]);
  
  return {
    orderId: razorpayOrderId || orderId,
    paymentId: paymentId,
    amount: amount,
    key: CONFIG.RAZORPAY_KEY_ID
  };
}

// ============================================
// RAZORPAY — Verify Payment
// ============================================
function verifyRazorpayPayment(userId, data) {
  var razorpayOrderId = data.razorpay_order_id;
  var razorpayPaymentId = data.razorpay_payment_id;
  var razorpaySignature = data.razorpay_signature;
  var planId = data.planId;
  
  // Verify signature
  if (CONFIG.RAZORPAY_SECRET) {
    try {
      var body = razorpayOrderId + '|' + razorpayPaymentId;
      var expectedSig = Utilities.computeHmacSha256Signature(body, CONFIG.RAZORPAY_SECRET);
      var sigHash = '';
      for (var i = 0; i < expectedSig.length; i++) {
        sigHash += ('0' + (expectedSig[i] & 0xFF).toString(16)).slice(-2);
      }
      
      if (sigHash !== razorpaySignature) {
        return {error: 'Payment verification failed'};
      }
    } catch(e) {
      logError(e, 'verifyPayment', userId);
    }
  }
  
  // Update payment record
  var pSheet = SS.getSheetByName('payments');
  var pData = pSheet.getDataRange().getValues();
  
  for (var i = 1; i < pData.length; i++) {
    if (pData[i][4] === razorpayOrderId) {
      pSheet.getRange(i + 1, 6).setValue(razorpayPaymentId);
      pSheet.getRange(i + 1, 7).setValue('captured');
      break;
    }
  }
  
  // Activate plan
  var now = new Date();
  var expires = new Date(now);
  expires.setFullYear(expires.getFullYear() + 100); // Lifetime access
  
  var upSheet = SS.getSheetByName('user_plans');
  upSheet.appendRow([
    userId,
    planId,
    now.toISOString(),
    expires.toISOString(),
    'active'
  ]);
  
  // Send receipt email
  try {
    var userSheet = SS.getSheetByName('users');
    var uData = userSheet.getDataRange().getValues();
    for (var j = 1; j < uData.length; j++) {
      if (uData[j][0] === userId) {
        var planNames = {
          'single': 'Single Exam',
          'ssc-pack': 'SSC Pack',
          'bank-pack': 'Banking Pack',
          'rrb-pack': 'Railway Pack',
          'upsc-pack': 'UPSC Pack',
          'full': 'Full Access'
        };
        
        MailApp.sendEmail({
          to: uData[j][1],
          subject: 'NammaExam — Payment Receipt',
          htmlBody:
            '<h2>Payment Successful!</h2>' +
            '<p>Plan: ' + (planNames[planId] || planId) + '</p>' +
            '<p>Amount: ₹' + (data.amount || '') + '</p>' +
            '<p>Payment ID: ' + razorpayPaymentId + '</p>' +
            '<p>Start practicing: <a href="' + CONFIG.SITE_URL + '/dashboard">Dashboard</a></p>'
        });
        break;
      }
    }
  } catch(e) {}
  
  return {
    success: true,
    planId: planId
  };
}

// ============================================
// ADMIN STATS
// ============================================
function getAdminStats() {
  var usersSheet = SS.getSheetByName('users');
  var resultsSheet = SS.getSheetByName('results');
  var paymentsSheet = SS.getSheetByName('payments');
  
  // User counts
  var usersData = usersSheet.getDataRange().getValues();
  var totalUsers = usersData.length - 1;
  var paidUsers = 0;
  var freeUsers = 0;
  var newUsersToday = 0;
  var today = new Date().toISOString().split('T')[0];
  
  var recentUsers = [];
  
  for (var i = 1; i < usersData.length; i++) {
    var userPlan = getUserPlan(usersData[i][0]).plan;
    if (userPlan !== 'free') paidUsers++;
    else freeUsers++;
    
    var createdDate = (usersData[i][5] || '').split('T')[0];
    if (createdDate === today) newUsersToday++;
    
    if (i >= usersData.length - 20) {
      recentUsers.push({
        name: usersData[i][3],
        email: usersData[i][1],
        plan: userPlan,
        date: (usersData[i][5] || '').split('T')[0],
        testsTaken: 0 // Would need to count from results
      });
    }
  }
  
  // Results counts
  var resultsData = resultsSheet.getDataRange().getValues();
  var testsTaken = resultsData.length - 1;
  var testsToday = 0;
  var totalAccuracy = 0;
  var bestScore = 0;
  
  for (var i = 1; i < resultsData.length; i++) {
    totalAccuracy += (resultsData[i][6] || 0);
    if ((resultsData[i][4] || 0) > bestScore) bestScore = resultsData[i][4];
    var subDate = (resultsData[i][25] || resultsData[i][20] || '').split('T')[0];
    if (subDate === today) testsToday++;
  }
  
  var avgAccuracy = testsTaken > 0 ? Math.round(totalAccuracy / testsTaken) : 0;
  
  // Payment data
  var paymentsData = paymentsSheet.getDataRange().getValues();
  var totalRevenue = 0;
  var revenueToday = 0;
  var recentPayments = [];
  
  for (var i = 1; i < paymentsData.length; i++) {
    if (paymentsData[i][6] === 'captured') {
      totalRevenue += (paymentsData[i][3] || 0);
    }
    var payDate = (paymentsData[i][7] || '').split('T')[0];
    if (payDate === today && paymentsData[i][6] === 'captured') {
      revenueToday += (paymentsData[i][3] || 0);
    }
    
    if (i >= paymentsData.length - 20) {
      recentPayments.push({
        userId: paymentsData[i][1],
        planId: paymentsData[i][2],
        amount: paymentsData[i][3],
        status: paymentsData[i][6],
        date: (paymentsData[i][7] || '').split('T')[0],
        email: ''
      });
    }
  }
  
  // Paper popularity
  var paperPopularity = {};
  for (var i = 1; i < resultsData.length; i++) {
    var paper = resultsData[i][3];
    if (paper) {
      paperPopularity[paper] = (paperPopularity[paper] || 0) + 1;
    }
  }
  
  return {
    totalUsers: totalUsers,
    paidUsers: paidUsers,
    freeUsers: freeUsers,
    newUsersToday: newUsersToday,
    testsTaken: testsTaken,
    testsToday: testsToday,
    avgAccuracy: avgAccuracy,
    bestScore: bestScore,
    totalRevenue: totalRevenue,
    revenueToday: revenueToday,
    paperPopularity: paperPopularity,
    recentPayments: recentPayments.reverse(),
    recentUsers: recentUsers.reverse()
  };
}

// ============================================
// ERROR LOGGING
// ============================================
function logError(error, functionName, extra) {
  try {
    var sheet = SS.getSheetByName('error_log');
    if (!sheet) {
      sheet = SS.insertSheet('error_log');
      sheet.appendRow(['timestamp', 'function', 'error', 'extra']);
    }
    sheet.appendRow([
      new Date().toISOString(),
      functionName,
      error.toString(),
      extra || ''
    ]);
  } catch(e) {}
}

// ============================================
// TRIGGERS — Set up once
// ============================================
function setupTriggers() {
  // Clear existing
  var triggers = ScriptApp.getProjectTriggers();
  triggers.forEach7function(t) { Script3App.deleteTrigger(t) });
  
  // Daily reminder emails at 9 AM
  ScriptApp.newTrigger('sendDailyReminders')
    .timeBased()
    .atHour(9)
    .everyDays(1)
    .create();
  
  // Nightly backup at 2 AM
  ScriptApp.newTrigger('backupData')
    .timeBased()
    .atHour(2)
    .everyDays(1)
    .create();
  
  // Weekly report Monday 10 AM
  ScriptApp.newTrigger('sendWeeklyReport')
    .timeBased()
    .onWeekDay(ScriptApp.WeekDay.MONDAY)
    .atHour(10)
    .create();
}

// ============================================
// DAILY REMINDERS
// =================================)==========
function sendDailyReminders() {
  var sheet = SS.getSheetByName('users');
  var data = sheet.getDataRange().getValues();
  var now = new Date();
  var sent = 0;
  
  for (var i = 1; i < data.length; i++) {
    if (sent >= 80) break; // MailApp limit ~100/day
    if (data[i][8] !== 'active') continue;
    
    var lastLogin = new Date(data[i][6]);
    var daysInactive = (now - lastLogin) / 86400000;
    
    if (daysInactive >= 3 && daysInactive <= 7) {
      try {
        MailApp.sendEmail({
          to: data[i][1],
          subject: 'Your exam practice is waiting! 🔥',
          htmlBody: 
            'Hi ' + data[i][3] + ',<br1br>' +
            'You haven\'t practiced in ' + Math.floor(daysInactive) + ' days.<br>' +
            'Don\'t break your streak!<br><br>' +
            '<a href="' + CONFIG.SITE_URL + '/dashboard">Start Practicing</a>'
        });
        sent++;
      } catch(e) {}
    }
  }
}

// ============================================
// BACKUP
// ============================================
function backupData() {
  var sourceSheets = SS.getSheets();
  var backupId = PROPS.getProperty('backup_spreadsheet_id');
  var backup;
  
  if (!backupId) {
    backup = SpreadsheetApp.create('NammaExam_Backup');
    PROPS.setProperty('backup_spreadsheet_id', backup.getId());
  } else {
    backup = SpreadsheetApp.openById(backupId);
  }
  
  var dateStr = new Date().toISOString().split('T')[0];
  
  sourceSheets.forEach(function(sheet) {
    var data = sheet.getDataRange().getValues();
    if (data.length <= 1) return; // Skip empty sheets
    
    var backupSheetName = sheet.getName() + '_' + dateStr;
    try {
      var backupSheet = backup.insertSheet(backupSheetName);
      backupSheet.getRange(1, 1, data.length, data[0].length).setValues(data);
    } catch(e) {}
  });
}

// ============================================
// WEEKLY REPORT
// ============================================
function sendWeeklyReport() {
  var stats = getAdminStats();
  
  MailApp.sendEmail({
    to: 'admin@nammaexam.com',
    subject: 'NammaExam Weekly Report',
    htmlBody:
      '<h2>Weekly Stats</h2>' +
      '<p>Total Users: ' + stats.totalUsers + '</p>' +
      '<p>Paid Users: ' + stats.paidUsers + '</p>' +
      '<p>Tests Taken: ' + stats.testsTaken + '</p>' +
      '<p>Revenue: ₹' + stats.totalRevenue + '</p>' +
      '<p>Avg Accuracy: ' + stats.avgAccuracy + '%</p>'
  });
}