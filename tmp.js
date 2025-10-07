const fs = require(''fs'');
const txt = fs.readFileSync('app/html/index.html', 'utf8');
const idx = txt.indexOf("q('#camDisplay')");
console.log(idx);
console.log(txt.slice(idx-120, idx+120));
