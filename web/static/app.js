// Naria : comportements UI minimes (compatibles CSP script-src 'self').

// Soumet automatiquement le formulaire d'un <select data-autosubmit> au changement,
// avec un retour visuel minimal le temps du rechargement (curseur d'attente + select
// grisé). La désactivation est différée d'un tick pour que la valeur du select soit
// déjà sérialisée dans la requête au moment où on le grise.
document.addEventListener("change", function (e) {
  var el = e.target;
  if (el && el.matches && el.matches("select[data-autosubmit]") && el.form) {
    el.form.submit();
    document.body.style.cursor = "progress";
    el.setAttribute("aria-busy", "true");
    setTimeout(function () { el.disabled = true; }, 0);
  }
});

// Confirmation avant soumission d'un <form data-confirm="...">.
document.addEventListener("submit", function (e) {
  var f = e.target;
  if (f && f.dataset && f.dataset.confirm && !window.confirm(f.dataset.confirm)) {
    e.preventDefault();
  }
});

// Anti double-soumission : au submit d'un formulaire de mutation (POST), on
// désactive le bouton pour éviter les doublons par double-clic (création d'un
// site ou d'un formulaire, actions d'administration). Enregistré après le handler data-confirm
// pour voir un e.defaultPrevented (confirmation annulée : on ne désactive rien).
document.addEventListener("submit", function (e) {
  var f = e.target;
  if (!f || !f.tagName || f.tagName !== "FORM") return;
  if (e.defaultPrevented) return; // annulation d'une confirmation
  var method = (f.getAttribute("method") || "get").toLowerCase();
  if (method !== "post") return; // on ne touche pas aux filtres GET

  if (f.dataset.submitting === "1") { e.preventDefault(); return; } // déjà en cours
  f.dataset.submitting = "1";

  // Tous les boutons de soumission du formulaire.
  var btns = f.querySelectorAll('button[type="submit"], button:not([type]), input[type="submit"]');
  var busy = e.submitter || btns[0]; // le bouton réellement cliqué, si le navigateur le fournit

  function release() {
    f.dataset.submitting = "";
    for (var i = 0; i < btns.length; i++) { btns[i].disabled = false; }
    if (busy) busy.removeAttribute("aria-busy");
  }

  // Différé d'un tick : la valeur du bouton cliqué (name/value) est déjà
  // sérialisée dans la requête au moment de la désactivation.
  setTimeout(function () {
    for (var i = 0; i < btns.length; i++) { btns[i].disabled = true; }
    if (busy) busy.setAttribute("aria-busy", "true");
  }, 0);

  // Filet de sécurité : si la navigation n'a pas lieu (erreur réseau, réponse sans
  // redirection), on réactive pour ne pas bloquer l'utilisateur.
  setTimeout(release, 15000);
});

// Retour du bfcache (bouton précédent) : réactive tout bouton resté désactivé.
window.addEventListener("pageshow", function (e) {
  if (!e.persisted) return;
  var forms = document.querySelectorAll('form[data-submitting="1"]');
  for (var i = 0; i < forms.length; i++) {
    forms[i].dataset.submitting = "";
    var bs = forms[i].querySelectorAll('button[type="submit"], button:not([type]), input[type="submit"]');
    for (var j = 0; j < bs.length; j++) { bs[j].disabled = false; bs[j].removeAttribute("aria-busy"); }
  }
});

// Menu mobile : le bouton hamburger ouvre/ferme la navigation principale
// (la nav est masquée en CSS sous 720px et révélée par la classe .open).
(function () {
  var toggle = document.querySelector(".nav-toggle");
  var nav = document.getElementById("main-nav");
  if (!toggle || !nav) return;
  toggle.addEventListener("click", function () {
    var open = nav.classList.toggle("open");
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
  });
})();

// Indicateur de disponibilité du service (pied de page) : ping /healthz toutes les 30 s.
(function () {
  var el = document.getElementById("health");
  if (!el) return;
  function set(ok) {
    el.textContent = "● " + (ok ? (el.dataset.online || "online") : (el.dataset.offline || "offline"));
    el.style.color = ok ? "var(--ok)" : "var(--err)";
  }
  function check() {
    fetch("/healthz", { cache: "no-store" })
      .then(function (r) { set(r.ok); })
      .catch(function () { set(false); });
  }
  check();
  setInterval(check, 30000);
})();

// Le thème est géré côté serveur : le lien .theme-toggle pointe sur /theme?to=…
// qui pose le cookie et recharge. data-theme est rendu par le serveur (ou par le
// petit script en <head> pour le repli prefers-color-scheme). Aucun JS ici.

// Copier dans le presse-papier le contenu de data-copy (bouton .copy-ref).
(function () {
  document.addEventListener("click", function (e) {
    var b = e.target.closest ? e.target.closest(".copy-ref") : null;
    if (!b || !navigator.clipboard) return;
    navigator.clipboard.writeText(b.getAttribute("data-copy") || "").then(function () {
      b.classList.add("copied");
      setTimeout(function () { b.classList.remove("copied"); }, 1200);
    });
  });
})();

// Raccourci clavier : « / » = focus sur la recherche.
(function () {
  document.addEventListener("keydown", function (e) {
    var t = e.target;
    if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable)) return;
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === "/") {
      var s = document.querySelector('input[type="search"]');
      if (s) { e.preventDefault(); s.focus(); }
    }
  });
})();
