// server.js
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const session = require("express-session");
const bodyParser = require("body-parser");
const multer = require("multer");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const path = require("path");
const fs = require("fs");

const app = express();
const db = new sqlite3.Database("./db.sqlite3");
const upload = multer({ dest: "public/uploads/" });

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(session({ secret: "secretKey", resave: false, saveUninitialized: false }));

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

// 언어 설정 미들웨어 : URL query, 쿠키 우선 적용.
app.use((req, res, next) => {
  let lang = req.query.lang || req.cookies.lang || "ko";
  res.locals.lang = lang;
  res.locals.text = i18n[lang];
  res.cookie("lang", lang, { maxAge: 86400000 });
  next();
});

// DB 초기화 : 테이블 생성
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    title TEXT, 
    content TEXT, 
    date TEXT, 
    category TEXT, 
    image TEXT,
    views INTEGER DEFAULT 0
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    username TEXT, 
    password TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    article_id INTEGER, 
    name TEXT, 
    comment TEXT, 
    date TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS subscribers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT
  )`);
  // 관리자 계정 생성 (초기 비밀번호 "1234" bcrypt 적용)
  const defaultPassword = "1234";
  const saltRounds = 10;
  bcrypt.hash(defaultPassword, saltRounds, (err, hash) => {
    db.run(
      "INSERT OR IGNORE INTO admins (id, username, password) VALUES (1, 'admin', ?)",
      [hash]
    );
  });
});

// 메인 페이지 - 기사 목록
app.get("/", (req, res) => {
  db.all("SELECT * FROM articles ORDER BY id DESC", (err, rows) => {
    res.render("index", { articles: rows, text: res.locals.text, lang: res.locals.lang });
  });
});

// 검색 기능 (제목, 내용 검색)
app.get("/search", (req, res) => {
  const q = `%${req.query.q || ""}%`;
  db.all("SELECT * FROM articles WHERE title LIKE ? OR content LIKE ? ORDER BY id DESC", [q, q], (err, rows) => {
    res.render("search", { articles: rows, text: res.locals.text, lang: res.locals.lang, query: req.query.q });
  });
});

// 기사 상세보기 + 조회수 증가 + 댓글 조회
app.get("/news/:id", (req, res) => {
  const articleId = req.params.id;
  db.run("UPDATE articles SET views = views + 1 WHERE id = ?", [articleId]);
  db.get("SELECT * FROM articles WHERE id = ?", [articleId], (err, row) => {
    if (!row) return res.send("존재하지 않는 기사입니다.");
    db.all("SELECT * FROM comments WHERE article_id = ? ORDER BY id DESC", [articleId], (cErr, comments) => {
      res.render("article", { article: row, comments, text: res.locals.text, lang: res.locals.lang });
    });
  });
});

// 댓글 작성
app.post("/news/:id/comment", (req, res) => {
  const { name, comment } = req.body;
  const date = new Date().toISOString().split("T")[0];
  db.run("INSERT INTO comments (article_id, name, comment, date) VALUES (?, ?, ?, ?)", [req.params.id, name, comment, date], () => {
    res.redirect(`/news/${req.params.id}?lang=${res.locals.lang}`);
  });
});

// 관리자 로그인 페이지
app.get("/admin/login", (req, res) => {
  res.render("login", { text: res.locals.text, lang: res.locals.lang });
});

// 관리자 로그인 처리 (bcrypt를 통한 비밀번호 비교)
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

// 관리자 대시보드: 기사 작성, 목록, 수정, 삭제, 뉴스레터 구독 폼 포함
app.get("/admin/dashboard", (req, res) => {
  if (!req.session.user) return res.redirect(`/admin/login?lang=${res.locals.lang}`);
  db.all("SELECT * FROM articles ORDER BY id DESC", (err, rows) => {
    res.render("dashboard", { articles: rows, text: res.locals.text, lang: res.locals.lang });
  });
});

// 기사 작성 처리 (Quill 에디터로 작성한 HTML 저장)
app.post("/admin/write", upload.single("image"), (req, res) => {
  if (!req.session.user) return res.redirect(`/admin/login?lang=${res.locals.lang}`);
  const { title, content, category } = req.body;
  const date = new Date().toISOString().split("T")[0];
  const image = req.file ? `/uploads/${req.file.filename}` : "";
  db.run("INSERT INTO articles (title, content, date, category, image) VALUES (?, ?, ?, ?, ?)", 
    [title, content, date, category, image],
    (err) => {
      if (err) console.error("DB 저장 오류:", err.message);
      res.redirect(`/admin/dashboard?lang=${res.locals.lang}`);
    }
  );
});

// 기사 수정 페이지
app.get("/admin/edit/:id", (req, res) => {
  if (!req.session.user) return res.redirect(`/admin/login?lang=${res.locals.lang}`);
  db.get("SELECT * FROM articles WHERE id = ?", [req.params.id], (err, row) => {
    res.render("edit", { article: row, text: res.locals.text, lang: res.locals.lang });
  });
});

// 기사 수정 처리
app.post("/admin/edit/:id", upload.single("image"), (req, res) => {
  if (!req.session.user) return res.redirect(`/admin/login?lang=${res.locals.lang}`);
  const { title, content, category } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : req.body.currentImage;
  db.run("UPDATE articles SET title = ?, content = ?, category = ?, image = ? WHERE id = ?", 
    [title, content, category, image, req.params.id],
    (err) => {
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

// 서버 실행
app.listen(3000, () => {
  console.log("✅ 서버 실행 중: http://localhost:3000");
});