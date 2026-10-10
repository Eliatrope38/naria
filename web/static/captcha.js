// Vérification anti-robot des formulaires. À charger par la page qui porte un
// <form data-naria-captcha> : avant l'envoi, le navigateur résout un calcul
// dont la solution part avec le formulaire, dans le champ « naria_captcha ».
//
// Le script ne retient rien dans le navigateur et ne contacte que l'instance
// visée par le formulaire, pour lui demander le défi. Il ne dépend pas de
// l'adresse d'où il est chargé : un site peut en servir sa propre copie.
(() => {
  const FIELD = "naria_captcha";
  // Bornes au-delà desquelles le script renonce : une difficulté que le temps
  // d'un envoi ne permet pas de résoudre, un défi qui n'arrive pas, un calcul
  // qui s'éternise. L'envoi part alors sans solution, et l'instance le refuse
  // avec un message que le visiteur peut lire.
  const MAX_BITS = 24;
  const FETCH_MS = 10000;
  const SOLVE_MS = 60000;
  // Essais entre deux pauses, pour que la page reste utilisable pendant le
  // calcul.
  const STEP = 20000;

  const K = new Int32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  const W = new Int32Array(64);

  // compress applique à l'état h la fonction de compression de SHA-256 sur les
  // 64 octets de b qui commencent à off.
  function compress(h, b, off) {
    for (let i = 0; i < 16; i++, off += 4) {
      W[i] = (b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3];
    }
    for (let i = 16; i < 64; i++) {
      const x = W[i - 15], y = W[i - 2];
      W[i] = (W[i - 16] + ((x >>> 7 | x << 25) ^ (x >>> 18 | x << 14) ^ (x >>> 3)) +
        W[i - 7] + ((y >>> 17 | y << 15) ^ (y >>> 19 | y << 13) ^ (y >>> 10))) | 0;
    }
    let a = h[0], b2 = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
    for (let i = 0; i < 64; i++) {
      const t1 = (k + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) +
        ((e & f) ^ (~e & g)) + K[i] + W[i]) | 0;
      const t2 = (((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) +
        ((a & b2) ^ (a & c) ^ (b2 & c))) | 0;
      k = g; g = f; f = e; e = (d + t1) | 0;
      d = c; c = b2; b2 = a; a = (t1 + t2) | 0;
    }
    h[0] += a; h[1] += b2; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += k;
  }

  // searcher prépare la recherche d'un compteur n tel que l'empreinte SHA-256
  // de prefix suivi de n commence par bits zéros. La fonction rendue essaie les
  // compteurs de from à to exclu, et rend le premier qui convient ou -1.
  //
  // Les blocs entiers de prefix sont hachés une fois pour toutes : chaque essai
  // ne coûte que le dernier bloc, qui porte la fin de prefix, le compteur et le
  // remplissage.
  function searcher(prefix, bits) {
    const bytes = new TextEncoder().encode(prefix);
    const mid = new Int32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    let done = 0;
    for (; done + 64 <= bytes.length; done += 64) compress(mid, bytes, done);
    const rest = bytes.length - done;
    // Au-delà, le compteur et le remplissage déborderaient du bloc, et les
    // empreintes seraient fausses sans que rien le signale.
    if (rest > 40) throw new Error("défi de longueur inattendue");
    const block = new Uint8Array(64);
    block.set(bytes.subarray(done));
    const h = new Int32Array(8);
    return (from, to) => {
      for (let n = from; n < to; n++) {
        const digits = String(n), end = rest + digits.length;
        for (let i = 0; i < digits.length; i++) block[rest + i] = digits.charCodeAt(i);
        block[end] = 0x80;
        const length = (done + end) * 8;
        block[62] = length >> 8;
        block[63] = length & 255;
        h.set(mid);
        compress(h, block, 0);
        if (h[0] >>> (32 - bits) === 0) return n;
      }
      return -1;
    };
  }

  // solve demande un défi à l'instance et en cherche la solution. endpoint est
  // l'adresse d'envoi du formulaire (…/submit ou …/f/CLÉ), key sa clé d'accès
  // quand l'adresse ne la porte pas.
  async function solve(endpoint, key) {
    const url = new URL(endpoint, document.baseURI);
    const inPath = /\/f\/([^/]+)\/?$/.exec(url.pathname);
    if (inPath) key = decodeURIComponent(inPath[1]);
    const base = url.origin + url.pathname.replace(/\/(submit|f\/[^/]+)\/?$/, "");
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), FETCH_MS);
    let challenge, difficulty;
    try {
      // L'instance rogne la clé à la réception du formulaire : le défi doit
      // être demandé pour la même.
      const res = await fetch(base + "/f/" + encodeURIComponent(key.trim()) + "/challenge", {
        credentials: "omit",
        referrerPolicy: "no-referrer",
        cache: "no-store",
        signal: abort.signal,
      });
      if (!res.ok) throw new Error("défi refusé : " + res.status);
      ({ challenge, difficulty } = await res.json());
    } finally {
      clearTimeout(timer);
    }
    if (!(difficulty >= 1 && difficulty <= MAX_BITS)) throw new Error("difficulté hors limites");
    const search = searcher(challenge + ".", difficulty);
    const deadline = Date.now() + SOLVE_MS;
    for (let from = 0; ; from += STEP) {
      const n = search(from, from + STEP);
      if (n >= 0) return challenge + "." + n;
      if (Date.now() > deadline) throw new Error("calcul trop long");
      await new Promise((resume) => setTimeout(resume));
    }
  }

  // Pour un site qui compose lui-même sa requête : la valeur rendue se place
  // dans le champ « naria_captcha », avant tout fichier.
  window.nariaCaptcha = solve;

  const solving = new WeakSet();
  // Formulaire dont l'envoi, relancé avec sa solution, doit passer tel quel.
  let solved = null;

  // En capture sur le document : avant les gestionnaires du site, qui ne voient
  // que l'envoi relancé, solution comprise.
  document.addEventListener("submit", (e) => {
    const form = e.target;
    if (!(form instanceof HTMLFormElement) || !form.hasAttribute("data-naria-captcha") || form === solved) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    if (solving.has(form)) return;
    solving.add(form);
    // Repère pour le style du site pendant le calcul.
    form.setAttribute("data-naria-captcha", "solving");

    const submitter = e.submitter;
    // getAttribute : un champ nommé « action » masquerait form.action.
    const action = (submitter && submitter.getAttribute("formaction")) || form.getAttribute("action") || "";
    const keyField = form.querySelector('[name="access_key"]');
    solve(action, keyField ? keyField.value : "")
      // Sans solution, l'envoi part quand même : l'instance le refuse avec un
      // message que le visiteur peut lire, dans sa langue.
      .catch(() => "")
      .then((solution) => {
        let input = form.querySelector('input[name="' + FIELD + '"]');
        if (!input) {
          input = document.createElement("input");
          input.type = "hidden";
          input.name = FIELD;
          // En tête : l'instance vérifie la solution avant de lire un fichier.
          form.prepend(input);
        }
        input.value = solution;
        form.setAttribute("data-naria-captcha", "");
        solving.delete(form);
        solved = form;
        try {
          // Par le prototype : un champ nommé « submit » masquerait form.submit.
          if (HTMLFormElement.prototype.requestSubmit) {
            // Un bouton que la page a retiré pendant le calcul ferait échouer
            // l'envoi.
            HTMLFormElement.prototype.requestSubmit.call(form, submitter && submitter.form === form ? submitter : null);
          } else {
            HTMLFormElement.prototype.submit.call(form);
          }
        } finally {
          solved = null;
        }
      });
  }, true);
})();
