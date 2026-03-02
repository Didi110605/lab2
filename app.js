// app.js
const express = require('express');
const helmet = require('helmet');
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const app = express();

// DOMPurify требует window-объект в Node.js
const { window } = new JSDOM('');
const purify = DOMPurify(window);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());


// Helmet + CSP
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      // запрещаем любые inline-скрипты и eval
      'script-src-attr': ["'none'"],
      'script-src-elem': ["'self'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'self'"],
    },
  })
);

app.set('view engine', 'ejs');


// "База данных" — в реальном проекте здесь должна быть настоящая БД
const comments = [];

app.get('/', (req, res) => {
  res.render('index', { comments });
});

// Добавление комментария
app.post('/comment', (req, res) => {
  let text = req.body.text?.trim() || '';

  // 1. Ограничение длины (валидация: не более 200 символов)
  if (text.length > 200) {
    text = text.substring(0, 200) + '…';
  }

  // 2. Санитизация (удаляем опасные теги и атрибуты)
  const cleanText = purify.sanitize(text, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li', 'code', 'pre'],
    ALLOWED_ATTR: ['href', 'target', 'rel'],
    FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed', 'svg'],
    FORBID_ATTR: ['on*'], // запрещаем все on... атрибуты (onclick, onload и т.д.)
  });

  // 3. Сохраняем уже очищенный текст
  comments.push(cleanText);

  res.redirect('/');
});


const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Сервер запущен → http://localhost:${PORT}`);
});