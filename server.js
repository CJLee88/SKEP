require('dotenv').config(); // .env 파일의 환경 변수를 불러옵니다.
// 환경변수 PORT가 설정되어 있으면 그 포트를, 없으면 기본 3000 포트를 사용합니다.

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const session = require("express-session");
const bodyParser = require("body-parser");
const multer = require("multer");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const path = require("path");
const fs = require("fs");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

// Passport 설정
passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((obj, done) => {
  done(null, obj);
});

// 자연어 처리 모듈 (TF-IDF)
const natural = require("natural");
const TfIdf = natural.TfIdf;

const app = express();

// DB 파일 경로를 환경 변수 DB_PATH에 따라 설정하고, 기본값은 /data/db.sqlite3로 변경합니다.
const dbPath = process.env.DB_PATH || "/data/db.sqlite3";
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error("Unable to open database:", err.message);
  } else {
    console.log(`Database opened at ${dbPath}`);
  }
});

// multer 설정 - diskStorage 사용
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "public/uploads/");
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  }
});
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 최대 5MB 제한
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("이미지 파일만 업로드 할 수 있습니다."));
    }
  }
});

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET, // 환경 변수에서 불러온 세션 시크릿 키
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 24 * 60 * 60 * 1000
    }
  })
);

// 다국어 텍스트 (한국어와 베트남어)
const i18n = {
  ko: {
    latest_news: "📰 최신 뉴스",
    article_list: "기사 목록",
    write_comment: "댓글 작성",
    name: "이름",
    comment: "댓글",
    login: "관리자 로그인",
    logout: "로그아웃",
    write: "작성 완료",
    view: "보기",
    edit: "수정",
    delete: "삭제",
    category: "카테고리",
    write_article: "새 기사 작성",
    search: "검색"
  },
  vi: {
    latest_news: "📰 Tin mới nhất",
    article_list: "Danh sách bài viết",
    write_comment: "Viết bình luận",
    name: "Tên",
    comment: "Bình luận",
    login: "Đăng nhập quản trị",
    logout: "Đăng xuất",
    write: "Hoàn tất viết",
    view: "Xem",
    edit: "Chỉnh sửa",
    delete: "Xóa",
    category: "Thể loại",
    write_article: "Viết bài mới",
    search: "Tìm kiếm"
  }
};

// 언어 설정 미들웨어
app.use((req, res, next) => {
  let lang = req.query.lang || req.cookies.lang || "ko";
  res.locals.lang = lang;
  res.locals.text = i18n[lang];
  res.cookie("lang", lang, { maxAge: 86400000 });
  next();
});

// 에러 처리 미들웨어 예시
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send(err.message);
});

// DB 초기화: 테이블 생성 (댓글 테이블에 user_email 컬럼 추가)
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS articles (
      id INTEGER PRIMARY KEY AUTOINCREMENT, 
      title TEXT, 
      content TEXT, 
      date TEXT, 
      category TEXT, 
      image TEXT,
      views INTEGER DEFAULT 0,
      keywords TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT, 
      username TEXT, 
      password TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT, 
      article_id INTEGER, 
      name TEXT, 
      comment TEXT, 
      date TEXT,
      user_email TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS subscribers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS visits (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      visit_date TEXT
    )
  `);

  // 관리자 계정 생성
  const defaultPassword = process.env.ADMIN_PASSWORD || "1234";
  const saltRounds = 10;
  bcrypt.hash(defaultPassword, saltRounds, (err, hash) => {
    if (err) {
      console.error("비밀번호 해시화 오류:", err.message);
      return;
    }
    db.run(
      "INSERT OR IGNORE INTO admins (id, username, password) VALUES (1, 'admin', ?)",
      [hash],
      (err) => {
        if (err) {
          console.error("관리자 계정 생성 오류:", err.message);
        } else {
          console.log("관리자 계정이 생성되었거나 이미 존재합니다.");
        }
      }
    );
  });
});

// Passport 구글 전략 설정
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL
},
(accessToken, refreshToken, profile, done) => {
  return done(null, profile);
}
));

// Passport 미들웨어 등록 (세션 미들웨어 이후)
app.use(passport.initialize());
app.use(passport.session());
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/auth/google/callback", (req, res, next) => {
  passport.authenticate("google", (err, user, info) => {
    if (err) { 
      return next(err); 
    }
    if (!user) {
      const lang = req.query.lang || req.cookies.lang || "ko";
      return res.redirect("/admin/login?lang=" + lang);
    }
    req.logIn(user, (err) => {
      if (err) { 
        return next(err); 
      }
      return res.redirect("/");
    });
  })(req, res, next);
});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ error: "로그인 후 이용하실 수 있습니다." });
}

// 방문자 기록 미들웨어
app.use((req, res, next) => {
  if (req.method === "GET" && req.path !== "/favicon.ico") {
    const today = new Date().toISOString().split("T")[0];
    db.run("INSERT INTO visits (visit_date) VALUES (?)", [today], err => {
      if (err) console.error("방문 기록 에러:", err.message);
    });
  }
  next();
});

// 관리자 상세 통계 페이지
app.get("/admin/detailed-stats", (req, res) => {
  if (!req.session.user) return res.redirect(`/admin/login?lang=${res.locals.lang}`);
  
  let startDate = req.query.start || new Date(Date.now() - (29 * 24 * 60 * 60 * 1000)).toISOString().split("T")[0];
  let endDate = req.query.end || new Date().toISOString().split("T")[0];
  
  db.all(
    `SELECT visit_date, COUNT(*) AS count 
     FROM visits 
     WHERE visit_date BETWEEN ? AND ?
     GROUP BY visit_date
     ORDER BY visit_date`,
    [startDate, endDate],
    (err, visitStats) => {
      if (err) {
        console.error("상세 방문자 통계 조회 오류:", err.message);
        visitStats = [];
      }
      db.all(
        `SELECT date AS article_date, COUNT(*) AS count 
         FROM articles 
         WHERE date BETWEEN ? AND ?
         GROUP BY date
         ORDER BY date`,
        [startDate, endDate],
        (err, articleStats) => {
          if (err) {
            console.error("상세 기사 통계 조회 오류:", err.message);
            articleStats = [];
          }
          res.render("detailed-stats", { 
            visitStats, articleStats, startDate, endDate,
            text: res.locals.text, lang: res.locals.lang
          });
        }
      );
    }
  );
});

// 관리자 대시보드
app.get("/admin/dashboard", (req, res) => {
  if (!req.session.user) return res.redirect(`/admin/login?lang=${res.locals.lang}`);
  const page = Number(req.query.page) || 1;
  const itemsPerPage = 10;
  const today = new Date().toISOString().split("T")[0];
  db.get("SELECT COUNT(*) AS todayCount FROM visits WHERE visit_date = ?", [today], (err, todayData) => {
    if (err) {
      console.error("오늘 방문자 조회 오류:", err.message);
      todayData = { todayCount: 0 };
    }
    db.all(
      "SELECT visit_date, COUNT(*) AS count FROM visits WHERE visit_date >= date(?, '-6 days') GROUP BY visit_date ORDER BY visit_date",
      [today],
      (err, statsRows) => {
        let totalCount = 0;
        if (statsRows) {
          statsRows.forEach(row => { totalCount += row.count; });
        }
        const averageCount = (statsRows && statsRows.length) ? Math.round(totalCount / statsRows.length) : 0;
        db.get("SELECT COUNT(*) AS todayArticles FROM articles WHERE date = ?", [today], (err, todayArticlesData) => {
          if (err) {
            console.error("오늘 기사 집계 오류:", err.message);
            todayArticlesData = { todayArticles: 0 };
          }
          db.get("SELECT COUNT(*) AS articles7days FROM articles WHERE date >= date(?, '-6 days')", [today], (err, articles7DaysData) => {
            if (err) {
              console.error("최근 7일 기사 집계 오류:", err.message);
              articles7DaysData = { articles7days: 0 };
            }
            db.get("SELECT COUNT(*) AS articles30days FROM articles WHERE date >= date(?, '-29 days')", [today], (err, articles30DaysData) => {
              if (err) {
                console.error("최근 30일 기사 집계 오류:", err.message);
                articles30DaysData = { articles30days: 0 };
              }
              db.get("SELECT COUNT(*) AS count FROM articles", (err, countResult) => {
                if (err) {
                  console.error("뉴스 개수 조회 오류:", err.message);
                  countResult = { count: 0 };
                }
                const totalItems = countResult.count;
                const totalPages = Math.ceil(totalItems / itemsPerPage);
                const offset = (page - 1) * itemsPerPage;
                db.all(`
                  SELECT a.*,
                    (SELECT COUNT(*) FROM comments WHERE comments.article_id = a.id) AS commentCount
                  FROM articles a
                  ORDER BY a.id DESC
                  LIMIT ? OFFSET ?
                `, [itemsPerPage, offset], (err, rows) => {
                  if (err) {
                    console.error("대시보드 기사 조회 오류:", err.message);
                    rows = [];
                  }
                  res.render("dashboard", {
                    articles: rows,
                    text: res.locals.text,
                    lang: res.locals.lang,
                    currentPage: page,
                    totalPages,
                    todayCount: todayData.todayCount,
                    averageCount,
                    todayArticles: todayArticlesData.todayArticles,
                    articles7days: articles7DaysData.articles7days,
                    articles30days: articles30DaysData.articles30days
                  });
                });
              });
            });
          });
        });
      }
    );
  });
});

// 인덱스 페이지 (일반 사용자용)
app.get("/", (req, res) => {
  const category = req.query.category || "";
  const page = Number(req.query.page) || 1;
  const itemsPerPage = 10;
  db.all(`
    SELECT a.*,
      (SELECT COUNT(*) FROM comments WHERE comments.article_id = a.id) AS commentCount
    FROM articles a
    WHERE views > 0
    ORDER BY views DESC
    LIMIT 3
  `, (err, popularArticles) => {
    if (err) {
      console.error("인기글 조회 오류:", err.message);
      popularArticles = [];
    }
    let countQuery = "SELECT COUNT(*) AS count FROM articles";
    let countParams = [];
    if (category.trim() !== "") {
      countQuery += " WHERE category = ?";
      countParams.push(category);
    }
    db.get(countQuery, countParams, (err, countResult) => {
      if (err) {
        console.error("뉴스 개수 조회 오류:", err.message);
        countResult = { count: 0 };
      }
      const totalItems = countResult.count;
      const totalPages = Math.ceil(totalItems / itemsPerPage);
      const offset = (page - 1) * itemsPerPage;
      let articlesQuery = `
        SELECT a.*,
          (SELECT COUNT(*) FROM comments WHERE comments.article_id = a.id) AS commentCount
        FROM articles a
      `;
      let queryParams = [];
      if (category.trim() !== "") {
        articlesQuery += " WHERE a.category = ? ";
        queryParams.push(category);
      }
      articlesQuery += " ORDER BY a.id DESC LIMIT ? OFFSET ?";
      queryParams.push(itemsPerPage, offset);
      db.all(articlesQuery, queryParams, (err, articles) => {
        if (err) {
          console.error("기사 목록 조회 오류:", err.message);
          articles = [];
        }
        res.render("index", { 
          articles, 
          popularArticles, 
          text: res.locals.text, 
          lang: res.locals.lang,
          category,
          currentPage: page,
          totalPages
        });
      });
    });
  });
});

// 검색 기능
app.get("/search", (req, res) => {
  const q = `%${req.query.q || ""}%`;
  db.all("SELECT * FROM articles WHERE title LIKE ? OR content LIKE ? ORDER BY id DESC", [q, q], (err, rows) => {
    if (err) {
      console.error("검색 오류:", err.message);
      return res.send("검색 오류가 발생했습니다.");
    }
    res.render("search", {
      articles: rows,
      text: res.locals.text,
      lang: res.locals.lang,
      query: req.query.q
    });
  });
});

// 기사 상세보기
app.get("/news/:id", (req, res) => {
  const articleId = req.params.id;
  db.run("UPDATE articles SET views = views + 1 WHERE id = ?", [articleId]);
  db.get("SELECT * FROM articles WHERE id = ?", [articleId], (err, row) => {
    if (!row) return res.send("존재하지 않는 기사입니다.");
    db.all("SELECT * FROM comments WHERE article_id = ? ORDER BY id DESC", [articleId], (cErr, comments) => {
      res.render("article", {
        article: row,
        comments,
        text: res.locals.text,
        lang: res.locals.lang,
        req: req
      });
    });
  });
});

// 새 기사 작성 페이지
app.get("/admin/write-form", (req, res) => {
  if (!req.session.user) return res.redirect(`/admin/login?lang=${res.locals.lang}`);
  res.render("admin-write", { text: res.locals.text, lang: res.locals.lang });
});

// 댓글 작성 (로그인한 사용자만)
app.post("/news/:id/comment", (req, res) => {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.send("댓글 작성을 위해 로그인이 필요합니다.");
  }
  const userEmail = req.user.emails && req.user.emails[0].value;
  const name = (req.user.emails && req.user.emails[0].value) || req.user.displayName || "User";
  const { comment } = req.body;
  const date = new Date().toISOString().split("T")[0];
  db.run("INSERT INTO comments (article_id, name, comment, date, user_email) VALUES (?, ?, ?, ?, ?)",
    [req.params.id, name, comment, date, userEmail],
    () => {
      res.redirect(`/news/${req.params.id}?lang=${res.locals.lang}`);
    }
  );
});

// 댓글 수정 페이지 (GET)
app.get("/news/:articleId/comment/:commentId/edit", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.send("댓글 수정을 위해 로그인이 필요합니다.");
  }
  const { articleId, commentId } = req.params;
  db.get("SELECT * FROM comments WHERE id = ?", [commentId], (err, commentRow) => {
    if (err) return res.send("DB 오류가 발생했습니다.");
    if (!commentRow) return res.send("댓글을 찾을 수 없습니다.");
    const userEmail = req.user.emails[0].value;
    if (commentRow.user_email !== userEmail) {
      return res.send("본인의 댓글만 수정할 수 있습니다.");
    }
    res.render("edit-comment", { articleId, comment: commentRow, lang: res.locals.lang });
  });
});

// 댓글 수정 처리 (POST)
app.post("/news/:articleId/comment/:commentId/edit", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.send("댓글 수정을 위해 로그인이 필요합니다.");
  }
  const { articleId, commentId } = req.params;
  const { comment } = req.body;
  const userEmail = req.user.emails[0].value;
  db.get("SELECT * FROM comments WHERE id = ?", [commentId], (err, row) => {
    if (err) return res.send("DB 오류 발생");
    if (!row) return res.send("댓글을 찾을 수 없습니다.");
    if (row.user_email !== userEmail) {
      return res.send("본인의 댓글만 수정할 수 있습니다.");
    }
    db.run("UPDATE comments SET comment = ? WHERE id = ?", [comment, commentId], (err) => {
      if (err) return res.send("댓글 수정 중 오류 발생");
      res.redirect(`/news/${articleId}?lang=${res.locals.lang}`);
    });
  });
});

// 댓글 삭제 처리 (본인 댓글만)
app.post("/news/:articleId/comment/:commentId/delete", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.send("댓글 삭제를 위해 로그인이 필요합니다.");
  }
  const { articleId, commentId } = req.params;
  const userEmail = req.user.emails[0].value;
  db.get("SELECT * FROM comments WHERE id = ?", [commentId], (err, row) => {
    if (err) return res.send("DB 오류 발생");
    if (!row) return res.send("댓글을 찾을 수 없습니다.");
    if (row.user_email !== userEmail) {
      return res.send("본인의 댓글만 삭제할 수 있습니다.");
    }
    db.run("DELETE FROM comments WHERE id = ?", [commentId], (err) => {
      if (err) return res.send("댓글 삭제 중 오류 발생");
      res.redirect(`/news/${articleId}?lang=${res.locals.lang}`);
    });
  });
});

// 관리자 댓글 삭제 (관리자 전용, 필요시)
app.post("/admin/delete-comment/:commentId", (req, res) => {
  if (!req.session.user) return res.redirect(`/admin/login?lang=${res.locals.lang}`);
  const commentId = req.params.commentId;
  db.run("DELETE FROM comments WHERE id = ?", [commentId], (err) => {
    if (err) {
      console.error("댓글 삭제 오류:", err.message);
      return res.send("댓글 삭제 중 오류가 발생했습니다.");
    }
    res.redirect('back');
  });
});

// 관리자 로그인 페이지
app.get("/admin/login", (req, res) => {
  res.render("login", { text: res.locals.text, lang: res.locals.lang });
});

// 관리자 로그인 처리
app.post("/admin/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM admins WHERE username = ?", [username], (err, row) => {
    if (!row) return res.send("로그인 실패");
    bcrypt.compare(password, row.password, (err, result) => {
      if (result) {
        req.session.user = row;
        res.redirect(`/admin/dashboard?lang=${res.locals.lang}`);
      } else {
        res.send("로그인 실패");
      }
    });
  });
});

// 관리자 로그아웃
app.get("/admin/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect(`/?lang=${res.locals.lang}`);
  });
});

// 기사 작성 처리 (파일 업로드 보안 강화 적용)
app.post("/admin/write", upload.single("image"), (req, res) => {
  if (!req.session.user) return res.redirect(`/admin/login?lang=${res.locals.lang}`);
  const { title, content, category } = req.body;
  const date = new Date().toISOString().split("T")[0];
  const image = req.file ? `/uploads/${req.file.filename}` : "";
  const stripHtmlTags = (html) => html.replace(/<[^>]*>/g, "");
  const plainText = stripHtmlTags(content);
  const tfidf = new TfIdf();
  tfidf.addDocument(plainText);
  let keywords = [];
  tfidf.listTerms(0)
    .sort((a, b) => b.tfidf - a.tfidf)
    .slice(0, 10)
    .forEach(item => { keywords.push(item.term); });
  const dynamicKeywords = keywords.join(', ');
  db.run(
    "INSERT INTO articles (title, content, date, category, image, keywords) VALUES (?, ?, ?, ?, ?, ?)",
    [title, content, date, category, image, dynamicKeywords],
    (err) => {
      if (err) {
        console.error("DB 저장 오류:", err.message);
      } else {
        console.log("✅ 글 저장 성공!");
      }
      res.redirect(`/admin/dashboard?lang=${res.locals.lang}`);
    }
  );
});

// 기사 수정 페이지
app.get("/admin/edit/:id", (req, res) => {
  if (!req.session.user) return res.redirect(`/admin/login?lang=${res.locals.lang}`);
  db.get("SELECT * FROM articles WHERE id = ?", [req.params.id], (err, row) => {
    if (err) {
      console.error("기사 조회 오류:", err.message);
      return res.send("기사 조회 중 오류가 발생했습니다.");
    }
    if (!row) return res.send("존재하지 않는 기사입니다.");
    res.render("edit", { article: row, text: res.locals.text, lang: res.locals.lang });
  });
});

// 기사 수정 처리
app.post("/admin/edit/:id", upload.single("image"), (req, res) => {
  if (!req.session.user) return res.redirect(`/admin/login?lang=${res.locals.lang}`);
  const { title, content, category } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : req.body.currentImage;
  db.run(
    "UPDATE articles SET title = ?, content = ?, category = ?, image = ? WHERE id = ?",
    [title, content, category, image, req.params.id],
    (err) => {
      if (err) {
        console.error("기사 수정 오류:", err.message);
      }
      res.redirect(`/admin/dashboard?lang=${res.locals.lang}`);
    }
  );
});

// 기사 삭제 처리 (첨부 이미지 삭제 포함)
app.post("/admin/delete/:id", (req, res) => {
  if (!req.session.user) return res.redirect(`/admin/login?lang=${res.locals.lang}`);
  db.get("SELECT image FROM articles WHERE id = ?", [req.params.id], (err, row) => {
    if (row && row.image) {
      const imgPath = path.join(__dirname, "public", row.image);
      if (fs.existsSync(imgPath)) fs.unlinkSync(imgPath);
    }
    db.run("DELETE FROM articles WHERE id = ?", [req.params.id], () => {
      db.run("DELETE FROM comments WHERE article_id = ?", [req.params.id], () => {
        res.redirect(`/admin/dashboard?lang=${res.locals.lang}`);
      });
    });
  });
});

// 뉴스레터 구독 처리
app.post("/subscribe", (req, res) => {
  const { email } = req.body;
  db.run("INSERT INTO subscribers (email) VALUES (?)", [email], () => {
    res.redirect(`/?lang=${res.locals.lang}`);
  });
});

// 검색 자동완성
app.get("/autocomplete", (req, res) => {
  let query = req.query.q || "";
  query = `%${query}%`;
  db.all("SELECT DISTINCT title FROM articles WHERE title LIKE ? LIMIT 5", [query], (err, rows) => {
    if (err) {
      console.error("자동완성 쿼리 오류:", err.message);
      return res.status(500).json([]);
    }
    const suggestions = rows.map(row => row.title);
    res.json(suggestions);
  });
});

// 서버 실행
const port = process.env.PORT || 8080;
app.listen(port, '0.0.0.0', () => {
  console.log(`✅ 서버 실행 중: http://0.0.0.0:${port}`);
});
