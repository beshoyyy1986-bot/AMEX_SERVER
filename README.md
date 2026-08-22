# AMEX TOOL - BESHOY MAGDY

## الملفات

| الملف | الوصف |
|-------|-------|
| `server.js` | السيرفر الرئيسي |
| `package.json` | dependencies |
| `bookmarklet.js` | كود الـ Bookmarklet |

---

## تشغيل السيرفر

```bash
npm install
npm start
```

السيرفر بيشتغل على: `http://localhost:3000`
تحقق إنه شغال: `http://localhost:3000/ping`

---

## إعداد الـ Bookmarklet

1. افتح `bookmarklet.js`
2. غيّر السطر الأول:
   ```js
   const SERVER_URL = 'http://localhost:3000'; // ← عنوان السيرفر
   ```
3. انسخ الكود كله
4. اعمل bookmark جديد في المتصفح
5. حط الكود في حقل الـ URL بدل الرابط

---

## الاستخدام

1. شغّل السيرفر أولاً
2. افتح صفحة الفوترة في Facebook Business Manager
3. اضغط على الـ Bookmark
4. اختار البطاقات
5. اضغط **ADD CARDS**
6. السيرفر هيتولى الباقي

---

## إعدادات التأخير

- اضغط ⚙️ في الأداة لتغيير الوقت بين كل بطاقة
- القيمة الافتراضية: 1 ثانية
- بيتحفظ تلقائياً في المتصفح
