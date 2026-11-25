// BlokBot – mobilní appka pro ovládání BlokBotu na Macu.
// Stav si stahuje z ntfy.sh (téma <tema>-s), příkazy posílá na <tema>-p.
// Všechno je šifrované AES-256-CBC + HMAC-SHA256 klíčem z párovacího kódu.
(function () {
  'use strict';

  var NTFY = 'https://ntfy.sh/';
  var KLIC_UL = 'blokbot-parovani';
  var $ = function (id) { return document.getElementById(id); };

  var par = null;          // { tema, klic }
  var klice = null;        // { enc, mac } (CryptoKey)
  var S = null;            // poslední stav z Macu
  var posledniStazeni = 0, posledniObnov = 0, rychleDo = 0, casovac = null, stahuji = false;
  var cekajici = {};       // akce → { cas, ocekavam(S) }

  // ------------------------------------------------------------------ šifrování
  function hexNaBajty(h) { var a = new Uint8Array(h.length / 2); for (var i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; }
  function bajtyNaHex(b) { return Array.prototype.map.call(b, function (x) { return (x < 16 ? '0' : '') + x.toString(16); }).join(''); }
  function b64NaBajty(s) { var t = atob(s), a = new Uint8Array(t.length); for (var i = 0; i < t.length; i++) a[i] = t.charCodeAt(i); return a; }
  function bajtyNaB64(b) { var s = ''; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); }
  function spoj(a, b) { var c = new Uint8Array(a.length + b.length); c.set(a, 0); c.set(b, a.length); return c; }

  function pripravKlice(klic) {
    return Promise.all([
      crypto.subtle.importKey('raw', hexNaBajty(klic.slice(0, 64)), { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']),
      crypto.subtle.importKey('raw', new TextEncoder().encode(klic.slice(64)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'])
    ]).then(function (k) { return { enc: k[0], mac: k[1] }; });
  }
  function gzip(text) {
    var s = new Blob([text]).stream().pipeThrough(new CompressionStream('gzip'));
    return new Response(s).arrayBuffer().then(function (b) { return new Uint8Array(b); });
  }
  function gunzip(bajty) {
    var s = new Blob([bajty]).stream().pipeThrough(new DecompressionStream('gzip'));
    return new Response(s).text();
  }
  function zasifruj(obj) {
    var iv = crypto.getRandomValues(new Uint8Array(16)), ct;
    return gzip(JSON.stringify(obj)).then(function (z) {
      return crypto.subtle.encrypt({ name: 'AES-CBC', iv: iv }, klice.enc, z);
    }).then(function (c) {
      ct = new Uint8Array(c);
      return crypto.subtle.sign('HMAC', klice.mac, spoj(iv, ct));
    }).then(function (mac) {
      return JSON.stringify({ v: 1, iv: bajtyNaHex(iv), ct: bajtyNaB64(ct), mac: bajtyNaB64(new Uint8Array(mac)) });
    });
  }
  function rozsifruj(text) {
    var z = JSON.parse(text);
    if (!z || z.v !== 1) return Promise.reject(new Error('neznámý formát'));
    var iv = hexNaBajty(z.iv), ct = b64NaBajty(z.ct);
    return crypto.subtle.verify('HMAC', klice.mac, b64NaBajty(z.mac), spoj(iv, ct)).then(function (ok) {
      if (!ok) throw new Error('neplatný podpis');
      return crypto.subtle.decrypt({ name: 'AES-CBC', iv: iv }, klice.enc, ct);
    }).then(function (p) { return gunzip(new Uint8Array(p)); }).then(JSON.parse);
  }

  // ------------------------------------------------------------------ spojení
  function stahni() {
    if (!par || stahuji) return Promise.resolve();
    stahuji = true;
    $('obnovit').classList.add('toci');
    return fetch(NTFY + par.tema + '-s/json?poll=1&since=latest', { cache: 'no-store' })
      .then(function (r) { if (!r.ok) throw new Error('server ' + r.status); return r.text(); })
      .then(function (t) {
        var radky = t.split('\n').filter(Boolean).map(function (r) { try { return JSON.parse(r); } catch (e) { return null; } })
          .filter(function (m) { return m && m.event === 'message'; });
        if (!radky.length) return null;
        return rozsifruj(radky[radky.length - 1].message);
      })
      .then(function (novy) {
        posledniStazeni = Date.now();
        if (novy && (!S || novy.cas >= S.cas)) { S = novy; vyhodnotCekajici(); vykresli(); }
        else vykresliCas();
      })
      .catch(function (e) { vykresliCas('Nepodařilo se načíst: ' + e.message); })
      .then(function () { stahuji = false; $('obnovit').classList.remove('toci'); });
  }

  function posli(akce, extra) {
    if (!par) return Promise.resolve(false);
    var prikaz = Object.assign({ akce: akce, cas: Date.now(), id: bajtyNaHex(crypto.getRandomValues(new Uint8Array(6))) }, extra || {});
    return zasifruj(prikaz).then(function (telo) {
      return fetch(NTFY + par.tema + '-p', { method: 'POST', body: telo });
    }).then(function (r) {
      if (!r.ok) throw new Error('server ' + r.status);
      rychleDo = Date.now() + 45000;
      if (akce === 'obnov') posledniObnov = Date.now();
      naplanuj(1500);
      return true;
    }).catch(function (e) { toast('Příkaz se nepodařilo odeslat: ' + e.message); return false; });
  }

  function naplanuj(za) {
    clearTimeout(casovac);
    if (document.hidden || !par) return;
    casovac = setTimeout(function () {
      var prace = stahni();
      if (Date.now() - posledniObnov > 120000) prace = prace.then(function () { return posli('obnov'); });
      prace.then(function () { naplanuj(Date.now() < rychleDo ? 3000 : 20000); });
    }, za);
  }

  // ------------------------------------------------------------------ příkazy s čekáním na potvrzení
  function prikaz(klic, akce, extra, ocekavam) {
    cekajici[klic] = { cas: Date.now(), ocekavam: ocekavam };
    vykresli();
    posli(akce, extra).then(function (ok) { if (!ok) { delete cekajici[klic]; vykresli(); } });
  }
  function vyhodnotCekajici() {
    Object.keys(cekajici).forEach(function (k) {
      var c = cekajici[k];
      if (S && S.cas > c.cas && c.ocekavam(S)) delete cekajici[k];
      else if (Date.now() - c.cas > 60000) { delete cekajici[k]; toast('Mac na příkaz neodpověděl. Běží BlokBot?'); }
    });
  }

  // ------------------------------------------------------------------ zobrazení
  var DNY = ['ne', 'po', 'út', 'st', 'čt', 'pá', 'so'];
  var NAZEV_DNE = ['Neděle', 'Pondělí', 'Úterý', 'Středa', 'Čtvrtek', 'Pátek', 'Sobota'];
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function zIso(s) { var p = s.split('-'); return new Date(+p[0], +p[1] - 1, +p[2]); }
  function iso(d) { return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()); }
  function fmtDen(s) { var d = zIso(s); return DNY[d.getDay()] + ' ' + d.getDate() + '. ' + (d.getMonth() + 1) + '.'; }
  function nazevDne(s) {
    var dnes = new Date(); var z = new Date(); z.setDate(z.getDate() + 1);
    if (s === iso(dnes)) return 'Dnes';
    if (s === iso(z)) return 'Zítra';
    return NAZEV_DNE[zIso(s).getDay()];
  }
  function blokText(b) { return b.k + 'K' + (b.start != null ? '/' + Math.floor(b.start / 60) + ':' + pad(b.start % 60) : ''); }
  function stari(ms) {
    var s = Math.round(ms / 1000);
    if (s < 10) return 'právě teď';
    if (s < 60) return 'před ' + s + ' s';
    if (s < 3600) return 'před ' + Math.round(s / 60) + ' min';
    return 'před ' + Math.round(s / 3600) + ' h';
  }
  function el(tag, trida, text, deti) {
    var e = document.createElement(tag);
    if (trida) e.className = trida;
    if (text != null) e.textContent = text;
    (deti || []).forEach(function (d) { if (d) e.appendChild(d); });
    return e;
  }
  function toast(t) {
    var e = $('toast'); e.textContent = t; e.classList.add('ukaz');
    clearTimeout(toast.c); toast.c = setTimeout(function () { e.classList.remove('ukaz'); }, 3500);
  }

  function vypocetStavu() {
    if (!S) return { druh: 'dim', text: 'Čekám na Mac…', popis: 'Mac zatím neposlal stav. Musí běžet BlokBot s zapnutou mobilní appkou.' };
    var staryStav = Date.now() - S.cas > 10 * 60000 && Date.now() - posledniObnov < 60000 && Date.now() - posledniObnov > 30000;
    if (staryStav) return { druh: 'err', text: 'Mac neodpovídá', popis: 'Poslední zpráva ' + stari(Date.now() - S.cas) + '. Je Mac zapnutý a běží BlokBot?' };
    if (S.wa == null || S.wa > 20) return { druh: 'err', text: 'Bez spojení s WhatsAppem', popis: 'Na Macu není otevřený WhatsApp Web v Safari.' };
    if (!S.stav.skupina) return { druh: 'warn', text: 'Vyber skupinu', popis: 'Na Macu otevři skupinu s bloky a v panelu klikni na Hlídat tuto skupinu.' };
    if (!S.stav.zapnuto) return { druh: 'dim', text: 'Vypnuto', popis: 'Bloky se neberou.' };
    if (S.chat && S.chat !== S.stav.skupina) return { druh: 'warn', text: 'Jiný chat na Macu', popis: 'Ve WhatsAppu na Macu je otevřený jiný chat než hlídaná skupina.' };
    if (S.stav.nasucho) return { druh: 'info', text: 'Hlídám na sucho', popis: 'Jen ukazuju, co bych vzal. Nic neodesílám.' };
    return { druh: 'ok', text: 'Hlídám', popis: 'Beru bloky podle pravidel.' };
  }

  function vykresliCas(chyba) {
    var t = chyba || (S ? 'Stav z Macu ' + stari(Date.now() - S.cas) : (posledniStazeni ? 'Mac zatím nic neposlal' : 'Načítám…'));
    $('aktualizace').textContent = t;
  }

  function radekBloku(b) {
    var stitky = [];
    if (b.stav === 'ceka') stitky.push(el('span', 'chip warn', 'čeká na potvrzení'));
    else if (b.stav === 'nepotvrzeno') stitky.push(el('span', 'chip err', 'žádost nepřišla'));
    else if (b.stav === 'konflikt') stitky.push(el('span', 'chip err', 'koliduje'));
    else if (b.stav === 'zadost') stitky.push(el('span', 'chip info', 'žádost'));
    else if (b.zdroj === 'portál') stitky.push(el('span', 'chip ok', 'v plánování'));
    else if (b.zdroj === 'ručně') stitky.push(el('span', 'chip', 'ručně'));
    var akce = [];
    var klicP = 'potvrdit:' + b.id, klicO = 'odebrat:' + b.id;
    if (b.stav === 'ceka' || b.stav === 'nepotvrzeno' || b.stav === 'konflikt') {
      var tlP = el('button', 'tl-mini', '✓'); tlP.setAttribute('aria-label', 'Označit jako potvrzený');
      tlP.disabled = !!cekajici[klicP];
      tlP.onclick = function () { prikaz(klicP, 'potvrdit', { blokId: b.id }, function (s) { return !s.rozvrh.some(function (x) { return x.id === b.id && x.stav !== 'moje'; }); }); };
      akce.push(tlP);
    }
    if (b.zdroj !== 'portál') {
      var tlO = el('button', 'tl-mini', '✕'); tlO.setAttribute('aria-label', 'Odebrat');
      tlO.disabled = !!cekajici[klicO];
      tlO.onclick = function () {
        if (!confirm('Odebrat blok ' + blokText(b) + ' (' + fmtDen(b.datum) + ')?')) return;
        prikaz(klicO, 'odebrat', { blokId: b.id }, function (s) { return !s.rozvrh.some(function (x) { return x.id === b.id; }); });
      };
      akce.push(tlO);
    }
    return el('div', 'blok', null, [el('div', 'roste', null, [el('div', 'blok-c', fmtDen(b.datum) + '  ' + blokText(b)), el('div', 'chipy', null, stitky)])].concat(akce));
  }

  function vykresli() {
    $('parovani').hidden = !!par && !vykresli.parovani;
    $('hlavni').hidden = !par || !!vykresli.parovani;
    if (!par || vykresli.parovani) return;
    vykresliCas();
    var s = vypocetStavu();
    $('s-tecka').className = 'tecka d-' + s.druh;
    $('s-titul').textContent = s.text;
    $('s-popis').textContent = s.popis;
    var pz = $('p-zapnuto'), pn = $('p-nasucho');
    var cz = cekajici.zapnuto, cn = cekajici.nasucho;
    pz.checked = cz ? cz.hodnota : !!(S && S.stav.zapnuto);
    pz.disabled = !S || !S.stav.skupina || !!cz;
    pn.checked = cn ? cn.hodnota : !!(S && S.stav.nasucho);
    pn.disabled = !S || !!cn;
    $('c-zapnuto').hidden = !cz; $('c-nasucho').hidden = !cn;

    var meta = $('s-meta'); meta.replaceChildren();
    if (S) {
      var r1 = el('div'); r1.append('Skupina ', el('b', null, S.stav.skupina || '–'), ' · ID ' + (S.id || '–'));
      var planText = S.planRezim === 'vypnuto' ? 'vypnuto' : (S.plan != null && S.plan < 30 ? 'připojeno' : 'není připojené');
      var r2 = el('div', null, 'Plánování: ' + planText + (S.stav.portalCas ? ' · bloky načteny ' + stari(Date.now() - S.stav.portalCas) : ''));
      meta.append(r1, r2);
    }

    var rozvrh = (S && S.rozvrh) || [];
    var cek = rozvrh.filter(function (b) { return b.stav === 'ceka' || b.stav === 'nepotvrzeno' || b.stav === 'konflikt'; });
    $('cekajici-obal').hidden = !cek.length;
    $('cekajici').replaceChildren.apply($('cekajici'), cek.map(radekBloku));

    var dny = $('dny'); dny.replaceChildren();
    var prehled = (S && S.prehled) || [];
    if (!prehled.length) {
      for (var i = 0; i < 4; i++) { var d = new Date(); d.setDate(d.getDate() + i); prehled.push({ datum: iso(d), moznosti: null }); }
    }
    prehled.forEach(function (p) {
      var bloky = rozvrh.filter(function (b) { return b.datum === p.datum; }).sort(function (a, b) { return (a.start || 0) - (b.start || 0); });
      var chipy = bloky.length ? bloky.map(function (b) { return el('span', 'chip' + (b.stav === 'ceka' ? ' warn' : ''), blokText(b)); }) : [el('span', 'chip', 'volno')];
      var mozn = p.moznosti == null ? [] : (p.moznosti.length
        ? [el('span', 'pozn', 'vezmu:')].concat(p.moznosti.map(function (m) { return el('span', 'chip ok', m); }))
        : [el('span', 'pozn', 'nic dalšího neberu')]);
      var obsah = el('div', null, null, [el('div', 'chipy', null, chipy)]);
      if (mozn.length) { var m2 = el('div', 'chipy', null, mozn); m2.style.marginTop = '6px'; obsah.appendChild(m2); }
      dny.appendChild(el('div', 'den', null, [el('div', 'den-n', nazevDne(p.datum), [el('small', null, fmtDen(p.datum).split(' ').slice(1).join(' '))]), obsah]));
    });

    var bl = $('bloky');
    var ostatni = rozvrh.slice().sort(function (a, b) { return a.datum < b.datum ? -1 : a.datum > b.datum ? 1 : (a.start || 0) - (b.start || 0); });
    bl.replaceChildren.apply(bl, ostatni.length ? ostatni.map(radekBloku) : [el('div', 'pozn', 'Žádné bloky na příštích 14 dní.')]);

    var dn = $('denik');
    var zaznamy = ((S && S.denik) || []).map(function (r) {
      var m = r.match(/^\d{4}-\d{2}-\d{2} (\d{2}:\d{2}):\d{2}\s+(.*)$/);
      return el('div', 'zaznam', null, [el('time', null, m ? m[1] : ''), el('span', null, m ? m[2] : r)]);
    });
    dn.replaceChildren.apply(dn, zaznamy.length ? zaznamy : [el('div', 'pozn', 'Zatím nic.')]);
  }

  // ------------------------------------------------------------------ spárování
  function nactiParovani(kod) {
    var m = String(kod || '').trim().match(/^BB1\.(bb-[0-9a-f]{16,})\.([0-9a-f]{128})$/);
    return m ? { tema: m[1], klic: m[2] } : null;
  }
  function pouzijParovani(p) {
    par = p;
    return pripravKlice(p.klic).then(function (k) {
      klice = k; S = null; posledniObnov = 0;
      vykresli.parovani = false;
      vykresli();
      stahni().then(function () { return posli('obnov'); }).then(function () { naplanuj(3000); });
    });
  }

  $('sparovat').onclick = function () {
    var p = nactiParovani($('kod').value);
    var ch = $('kod-chyba');
    if (!p) { ch.hidden = false; ch.textContent = 'Tohle není párovací kód. Zkopíruj ho celý z panelu BlokBot na Macu (začíná BB1.).'; return; }
    ch.hidden = true;
    try { localStorage.setItem(KLIC_UL, JSON.stringify(p)); } catch (e) { /* nic */ }
    $('kod').value = '';
    pouzijParovani(p).then(function () { toast('Spárováno ✓'); });
  };
  $('nastaveni').onclick = function () {
    vykresli.parovani = !vykresli.parovani || !par;
    $('zrusit-parovani').hidden = !par; $('odparovat').hidden = !par;
    vykresli();
  };
  $('zrusit-parovani').onclick = function () { vykresli.parovani = false; vykresli(); };
  $('odparovat').onclick = function () {
    if (!confirm('Odpojit tento telefon od BlokBotu?')) return;
    try { localStorage.removeItem(KLIC_UL); } catch (e) { /* nic */ }
    par = null; klice = null; S = null; vykresli.parovani = false; vykresli();
  };
  $('obnovit').onclick = function () { if (par) stahni().then(function () { return posli('obnov'); }); };
  $('p-zapnuto').onchange = function () {
    var v = this.checked;
    cekajici.zapnuto = { cas: Date.now(), hodnota: v, ocekavam: function (s) { return s.stav.zapnuto === v; } };
    vykresli();
    posli(v ? 'zapnout' : 'vypnout').then(function (ok) { if (!ok) { delete cekajici.zapnuto; vykresli(); } });
  };
  $('p-nasucho').onchange = function () {
    var v = this.checked;
    cekajici.nasucho = { cas: Date.now(), hodnota: v, ocekavam: function (s) { return s.stav.nasucho === v; } };
    vykresli();
    posli('nasucho', { hodnota: v }).then(function (ok) { if (!ok) { delete cekajici.nasucho; vykresli(); } });
  };

  document.addEventListener('visibilitychange', function () {
    if (!document.hidden && par) { stahni().then(function () { return posli('obnov'); }); }
    else clearTimeout(casovac);
  });
  setInterval(function () { if (par && !document.hidden) { vyhodnotCekajici(); vykresliCas(); } }, 5000);

  // ------------------------------------------------------------------ start
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(function () {});
  var zHashe = nactiParovani(decodeURIComponent((location.hash.match(/p=([^&]+)/) || [])[1] || ''));
  if (zHashe) { try { localStorage.setItem(KLIC_UL, JSON.stringify(zHashe)); } catch (e) { /* nic */ } history.replaceState(null, '', location.pathname); }
  var ulozene = zHashe;
  if (!ulozene) { try { ulozene = JSON.parse(localStorage.getItem(KLIC_UL) || 'null'); } catch (e) { ulozene = null; } }
  if (ulozene && ulozene.tema && ulozene.klic) pouzijParovani(ulozene);
  else { vykresli(); $('aktualizace').textContent = 'Nespárováno'; }

  window.__blokbotMobil = { _test: { zasifruj: zasifruj, rozsifruj: rozsifruj, pripravKlice: pripravKlice, stav: function () { return S; }, nastavNtfy: function (u) { NTFY = u; } } };
})();
