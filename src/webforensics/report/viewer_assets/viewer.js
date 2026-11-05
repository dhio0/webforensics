"use strict";
(function () {
  // Every string comes from the embedded JSON (often attacker-controlled log text).
  // It is only ever set with textContent or as an attribute value; never as markup.
  var D = JSON.parse(document.getElementById("data").textContent);
  var U = D.ui;
  var SVGNS = "http://www.w3.org/2000/svg";
  var PAGE = 200;
  var DIGITS = Math.max(2, String(D.events.length).length);

  // A query value is marked when it holds characters or keywords that attacks use. This is
  // only a reading aid on the page; the analysis itself never uses it.
  var ATTACK = /'|"|--|\/\*|\|\||;|`|\$\(|\.\.[\/\\]|<\s*\/?\s*script|\b(?:union|select|sleep|benchmark|exec|system|passthru|shell_exec)\b|\b(?:or|and)\b\s+\S+\s*=/gi;

  // Combined log format, as the analysis parsed it. Used only to show the line's fields;
  // a line that does not match is shown whole.
  var COMBINED = /^(\S+) (\S+) (\S+) \[([^\]]+)\] "((?:[^"\\]|\\.)*)" (\d{3}) (\d+|-) "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)"(?: "((?:[^"\\]|\\.)*)")?$/;

  // Ticks are kept in this browser only (localStorage), keyed by case; the page works without.
  var STORE = "webforensics:" + D.caseId + ":actions";

  function fmt(template, values) {
    return template.replace(/\{(\w+)\}/g, function (_, k) {
      return Object.prototype.hasOwnProperty.call(values, k) ? String(values[k]) : "?";
    });
  }

  function el(tag, props) {
    var node = document.createElement(tag);
    if (props) {
      for (var k in props) {
        if (!Object.prototype.hasOwnProperty.call(props, k)) continue;
        var v = props[k];
        if (v === null || v === undefined || v === false) continue;
        if (k === "text") node.textContent = v;
        else if (k === "cls") node.className = v;
        else if (k.slice(0, 2) === "on") node.addEventListener(k.slice(2), v);
        else node.setAttribute(k, v === true ? "" : v);
      }
    }
    for (var i = 2; i < arguments.length; i++) {
      var kid = arguments[i];
      if (kid === null || kid === undefined || kid === false) continue;
      node.appendChild(typeof kid === "string" ? document.createTextNode(kid) : kid);
    }
    return node;
  }

  function sv(tag, attrs) {
    var node = document.createElementNS(SVGNS, tag);
    for (var k in attrs) {
      if (Object.prototype.hasOwnProperty.call(attrs, k)) node.setAttribute(k, attrs[k]);
    }
    return node;
  }

  function titleNode(text) {
    var t = document.createElementNS(SVGNS, "title");
    t.textContent = text;
    return t;
  }

  function no(n) {
    var s = String(n);
    while (s.length < DIGITS) s = "0" + s;
    return "#" + s;
  }

  function glyph(cat) { return el("i", { cls: "g g-" + cat, "aria-hidden": "true" }); }

  function conf(level, label) { return el("span", { cls: "conf c-" + level, text: label }); }

  function pairs(dl, label, value) {
    dl.appendChild(el("dt", { text: label }));
    dl.appendChild(typeof value === "string" ? el("dd", { text: value }) : el("dd", null, value));
  }

  // --- state -----------------------------------------------------------------------------

  var events = D.events;
  var byN = {};
  events.forEach(function (e) {
    byN[e.n] = e;
    var cites = e.cites.map(function (i) { return D.cites[i].ref + " " + D.cites[i].ex; });
    e.search = (e.text + " " + e.actor + " " + e.time + " " + cites.join(" ")).toLowerCase();
  });
  var laneOf = {};
  D.lanes.forEach(function (a, i) { laneOf[a] = i; });
  var attacker = {};
  D.attackers.forEach(function (a) { attacker[a] = true; });
  var hasOthers = events.some(function (e) { return !(e.actor in laneOf); });

  var state = { tab: "overview", sel: null, q: "", actor: "*", story: false, limit: PAGE,
    cats: {}, open: {}, zoom: null };
  D.categories.forEach(function (c) { state.cats[c.id] = true; });

  // --- frame: one header line, the sections as text tabs, then the page -------------------

  var bad = D.verdict.compromised;
  var app = document.getElementById("app");
  var stats = D.verdict.stats;
  var X = D.detail;
  var docBy = {};
  D.doc.forEach(function (s) { docBy[s.anchor] = s; });

  // "#laporan" is the full report, opened in its own tab from the header link.
  if (location.hash === "#laporan") { buildReport(); return; }

  app.appendChild(el("header", { cls: "top" },
    el("div", { cls: "top-l" },
      el("span", { cls: "brand", text: "webforensics" }),
      el("span", { cls: "case", text: U["meta.case"] + " " + D.caseId })),
    el("div", { cls: "top-r" },
      el("span", { text: U["meta.generated"] + " " + D.generated }),
      el("a", { cls: "report-link", href: "#laporan", target: "_blank", rel: "noopener",
        title: U["report.open_hint"], text: U["report.open"] }))));

  var nav = el("nav", { cls: "nav", role: "tablist" });
  app.appendChild(nav);
  var main = el("main", { cls: "page" });
  app.appendChild(main);
  var panels = {}, badges = {};
  D.tabs.forEach(function (tab, i) {
    badges[tab.id] = tab.count ? el("span", { cls: "tab-n", text: String(tab.count) }) : null;
    nav.appendChild(el("button", {
      role: "tab", id: "tab-" + tab.id, "aria-controls": "panel-" + tab.id,
      title: fmt(U["tab.key"], { key: i + 1 }),
      onclick: function () { showTab(tab.id, true); }
    }, tab.label, badges[tab.id]));
    var panel = el("section", { role: "tabpanel", id: "panel-" + tab.id, "aria-labelledby": "tab-" + tab.id });
    panel.hidden = true;
    panels[tab.id] = panel;
    main.appendChild(panel);
    if (tab.id === "overview") buildOverview(panel, tab);
    else if (tab.id === "timeline") buildTimeline(panel);
    else tab.anchors.forEach(function (a) { panel.appendChild(section(a)); });
  });
  app.appendChild(el("footer", { cls: "foot" },
    el("span", { text: U.generated_by }), el("span", { cls: "keys", text: U.keys })));

  nav.addEventListener("keydown", function (ev) {
    var back = ev.key === "ArrowLeft", fwd = ev.key === "ArrowRight";
    if (!back && !fwd) return;
    ev.preventDefault();
    var ids = D.tabs.map(function (t) { return t.id; });
    var i = ids.indexOf(state.tab) + (back ? -1 : 1);
    showTab(ids[(i + ids.length) % ids.length], true);
    document.getElementById("tab-" + state.tab).focus();
  });

  // "#timeline:12" opens event 12, so one finding can be shared as a link.
  function route(hash) {
    if (hash === "laporan") { location.reload(); return; }
    var m =/^timeline:(\d+)$/.exec(hash);
    if (m && byN[Number(m[1])]) { showTab("timeline", false); select(Number(m[1]), true); return; }
    showTab(hash || "overview", false);
  }

  function showTab(id, push) {
    if (!panels[id]) id = "overview";
    state.tab = id;
    D.tabs.forEach(function (t) {
      var on = t.id === id;
      panels[t.id].hidden = !on;
      var b = document.getElementById("tab-" + t.id);
      b.setAttribute("aria-selected", on ? "true" : "false");
      b.tabIndex = on ? 0 : -1;
    });
    if (push && location.hash !== "#" + id) history.replaceState(null, "", "#" + id);
    // A tab opens at its top, with the tab bar in view.
    if (push && window.scrollY > 0) window.scrollTo(0, 0);
    if (id === "timeline") drawChart();
  }

  window.addEventListener("hashchange", function () { route(location.hash.slice(1)); });

  // Keyboard, as in the tools analysts already use. Not while typing in a field.
  document.addEventListener("keydown", function (ev) {
    var t = ev.target, typing = t && (t.tagName === "INPUT" || t.tagName === "SELECT" || t.tagName === "TEXTAREA");
    if (ev.key === "Escape") {
      if (typing) t.blur();
      document.body.classList.remove("inspecting");
      return;
    }
    if (typing || ev.ctrlKey || ev.metaKey || ev.altKey) return;
    if (/^[1-9]$/.test(ev.key) && D.tabs[Number(ev.key) - 1]) {
      showTab(D.tabs[Number(ev.key) - 1].id, true);
    } else if (ev.key === "/") {
      ev.preventDefault();
      showTab("timeline", true);
      searchBox.focus();
    } else if (ev.key === "j" || ev.key === "k") {
      if (state.tab !== "timeline") showTab("timeline", true);
      step(ev.key === "j" ? 1 : -1);
    }
  });

  // --- overview: the backtrace and the case facts -----------------------------------------

  function story() {
    return events.filter(function (e) { return e.story || e.root; });
  }

  // A file is cited as "path @hash"; the path is already in the text, so show the hash.
  function proof(e) {
    var cite = e.cites.length ? D.cites[e.cites[0]].ref : "", at = cite.lastIndexOf(" @");
    return { full: cite, short: at > 0 ? cite.slice(at + 1) : cite };
  }

  // Identical files written in the same second (a judol kit, an unpacked archive) are one
  // step with a count, as in the report's attack story (D98). The register keeps each one.
  function chainSteps() {
    var steps = [];
    story().forEach(function (e) {
      var last = steps[steps.length - 1], p = proof(e);
      if (last && e.cat === "file" && last.e.cat === "file" && last.e.clock === e.clock &&
          last.hash && last.hash === p.short && p.short.charAt(0) === "@") {
        last.more += 1;
        return;
      }
      steps.push({ e: e, more: 0, hash: p.short });
    });
    return steps;
  }

  function heroText() {
    var root = D.verdict.root;
    if (!bad) return U["hero.clean"];
    if (!root) return U["hero.no_root"];
    return root.vulnKnown ? fmt(U["hero.root"], { vuln: root.vuln }) : U["hero.root_unknown"];
  }

  function buildOverview(panel, tab) {
    var steps = chainSteps();
    var chain = el("ol", { cls: "chain", "aria-label": U["chain.title"] });
    steps.forEach(function (s) {
      var e = s.e, p = proof(e);
      var open = function () { openEvent(e.n); };
      chain.appendChild(el("li", {
        cls: "step c-" + e.conf + (e.root ? " root" : ""), tabindex: "0",
        onclick: open,
        onkeydown: function (ev) { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); open(); } }
      },
        el("span", { cls: "node", "aria-hidden": "true" }, glyph(e.cat)),
        el("div", { cls: "step-body" },
          el("div", { cls: "step-head" },
            el("span", null, el("span", { cls: "n", text: no(e.n) }),
              el("span", { cls: "role", text: e.root ? U["chain.root"] : (U["role." + e.cat] || U["role.other"]) })),
            el("span", { text: e.day + " " + e.clock })),
          el("p", { cls: "step-text", text: e.text }),
          el("div", { cls: "step-proof" },
            el("span", { cls: "proof", title: p.full, text: p.short }),
            conf(e.conf, fmt(U["chain.strength"], { level: e.confLabel }))),
          s.more ? el("div", { cls: "step-more", text: fmt(U["chain.more"], { count: s.more }) }) : null)));
    });

    var legend = el("p", { cls: "legend" }, el("span", { text: U["chain.legend"] }),
      conf("high", U["chain.legend_high"]), conf("medium", U["chain.legend_medium"]),
      conf("low", U["chain.legend_low"]));

    var hero = el("div", { cls: "hero" + (bad ? " bad" : "") },
      el("h1", { text: heroText() }),
      el("p", { text: steps.length ? U["chain.lead"] : U["chain.none"] }));

    var summary = el("div", { cls: "summary" }, el("h2", { text: U["summary.title"] }));
    tab.anchors.forEach(function (a) {
      var s = docBy[a];
      for (var i = 0; i < s.blocks.length && s.blocks[i].t !== "h"; i++) summary.appendChild(docBlock(s.blocks[i]));
    });

    panel.appendChild(hero);
    panel.appendChild(el("div", { cls: "overview" },
      el("div", { cls: "ov-main" }, steps.length ? chain : null, steps.length ? legend : null, summary),
      facts()));
  }

  function facts() {
    var v = D.verdict, dl = el("dl", { cls: "facts" });
    pairs(dl, U["facts.verdict"], el("span", { cls: bad ? "bad" : null,
      text: bad ? U["stamp.compromised"] : U["stamp.clean"] }));
    if (v.root) {
      var entry = el("a", { href: "#timeline",
        onclick: function (ev) { ev.preventDefault(); openEvent(v.root.n); } }, no(v.root.n));
      pairs(dl, U["facts.entry"], el("span", null, entry, " " + v.root.day + " " + v.root.clock + " " + D.zoneShort));
      pairs(dl, U["facts.vuln"], v.root.vuln);
      pairs(dl, U["facts.confidence"], conf(v.root.conf, v.root.confLabel));
    } else if (bad) {
      pairs(dl, U["facts.entry"], U["facts.no_root"]);
    }
    pairs(dl, U["facts.attackers"], D.attackers.length ? el("span", { cls: "mono", text: D.attackers.join("\n") }) : U["facts.none"]);
    var own = events.filter(function (e) { return attacker[e.actor]; });
    if (own.length) {
      var a = own[0], b = own[own.length - 1];
      pairs(dl, U["facts.window"], a.day + " " + a.clock + "\n" + b.day + " " + b.clock);
    }
    pairs(dl, U["meta.zone"], D.zone);
    var scope = el("p", { cls: "scope-line", text: fmt(U["facts.scope"], {
      events: stats.events, files: stats.files, actors: stats.actors, gaps: stats.gaps }) });
    return el("aside", { cls: "ov-side" }, el("h2", { text: U["facts.title"] }), dl, scope);
  }

  function openEvent(n) {
    showTab("timeline", true);
    select(n, true);
  }

  // --- sections: the report's text, or a richer view of the same facts -------------------

  // Root cause, files, IOCs, gaps and actions are drawn from `detail`, so every number and
  // value links back into the timeline. Each falls back to the report's text when empty.
  function section(anchor) {
    var s = docBy[anchor];
    if (anchor === "akar-masalah" && X.root) return buildRoot(s);
    if (anchor === "akar-masalah" && X.gaps.rows.length) {
      // No entry point: the gaps are where it may have been lost.
      var none = docSection(s);
      none.appendChild(el("p", { cls: "warn" },
        el("span", { text: U["root.none_hint"] + " " }),
        el("button", { cls: "link", text: U["root.none_gaps"], onclick: function () { showTab("gaps", true); } })));
      return none;
    }
    if (anchor === "file-terdampak" && (X.files.files.length || X.files.logOnly)) return buildFiles(s);
    if (anchor === "ioc" && X.iocs.length) return buildIocs(s);
    if (anchor === "celah-bukti" && X.gaps.rows.length) return buildGaps(s);
    if (anchor === "tindakan" && X.actions.length) return buildActions(s);
    return docSection(s);
  }

  function copyText(text, button, label) {
    function done() {
      button.textContent = U.copied;
      setTimeout(function () { button.textContent = label || U.copy; }, 1200);
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text) && done(); });
    } else if (fallbackCopy(text)) {
      done();
    }
  }

  function fallbackCopy(text) {
    var area = el("textarea", { readonly: true, "aria-hidden": "true", cls: "offscreen" });
    area.value = text;
    document.body.appendChild(area);
    area.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (_) { ok = false; }
    document.body.removeChild(area);
    return ok;
  }

  function copyButton(text, label) {
    var b = el("button", { cls: "link copy", text: label || U.copy });
    b.addEventListener("click", function (ev) { ev.stopPropagation(); copyText(text, b, label); });
    return b;
  }

  // "#5" that opens the event in the timeline.
  function eventLink(n) {
    return el("button", { cls: "chip", title: byN[n] ? byN[n].text : "", text: no(n),
      onclick: function () { openEvent(n); } });
  }

  function eventLinks(list) {
    var box = el("span", { cls: "chips" });
    list.forEach(function (n) { box.appendChild(eventLink(n)); });
    return box;
  }

  // Show the timeline filtered by an address (as actor) or by any other text (as search).
  function lookUp(value, asActor) {
    showTab("timeline", true);
    resetFilters();
    if (asActor && actorList().indexOf(value) >= 0) {
      state.actor = value;
      panels.timeline.querySelector("select").value = value;
    } else {
      state.q = value.toLowerCase();
      searchBox.value = value;
    }
    state.limit = PAGE;
    refresh();
    panels.timeline.scrollIntoView({ block: "start" });
  }

  function zoomTo(from, to) {
    showTab("timeline", true);
    resetFilters();
    var pad = Math.max((to - from) * 0.5, 60000);
    state.zoom = [from - pad, to + pad];
    refresh();
  }

  function resetFilters() {
    state.q = ""; state.actor = "*"; state.story = false; state.zoom = null;
    D.categories.forEach(function (c) { state.cats[c.id] = true; });
    syncFilterControls();
  }

  // --- root cause: the request, why it is the entry, and the vulnerable code --------------

  function decode(s) {
    try { return decodeURIComponent(s.replace(/\+/g, " ")); } catch (_) { return s; }
  }

  function queryParams(query) {
    if (!query) return [];
    return query.split("&").filter(Boolean).map(function (part) {
      var i = part.indexOf("=");
      return { k: decode(i >= 0 ? part.slice(0, i) : part), v: decode(i >= 0 ? part.slice(i + 1) : "") };
    });
  }

  // The value as text nodes, with what looks like attack syntax inside <mark>.
  function marked(value) {
    var box = el("span", { cls: "pv" }), last = 0, hit = false, m;
    ATTACK.lastIndex = 0;
    while ((m = ATTACK.exec(value)) !== null) {
      if (!m[0]) { ATTACK.lastIndex++; continue; }
      if (m.index > last) box.appendChild(document.createTextNode(value.slice(last, m.index)));
      box.appendChild(el("mark", { text: m[0] }));
      last = m.index + m[0].length;
      hit = true;
    }
    if (last < value.length) box.appendChild(document.createTextNode(value.slice(last)));
    if (!value) box.appendChild(el("span", { cls: "muted", text: U["param.empty"] }));
    return { node: box, hit: hit };
  }

  function paramTable(query) {
    var list = queryParams(query);
    if (!list.length) return null;
    var table = el("table", { cls: "params" });
    list.forEach(function (p) {
      var v = marked(p.v);
      table.appendChild(el("tr", { cls: v.hit ? "hit" : null },
        el("th", { cls: "mono", text: p.k }), el("td", { cls: "mono" }, v.node)));
    });
    return table;
  }

  function requestCard(req) {
    var parsed = dissect(req.raw), card = el("div", { cls: "req" });
    if (parsed) {
      var f = {};
      parsed.fields.forEach(function (x) { f[x[0]] = x[1]; });
      card.appendChild(el("div", { cls: "req-line mono" },
        el("span", { cls: "req-m", text: f.method || "" }),
        el("span", { cls: "req-p", text: f.path || "" }),
        el("span", { cls: "req-s", text: fmt(U["req.status"], { status: f.status || "-", bytes: f.bytes || "-" }) })));
      var params = paramTable(f.query);
      if (params) {
        card.appendChild(params);
        if (params.querySelector("tr.hit")) card.appendChild(el("p", { cls: "req-note", text: U["param.marked"] }));
      }
    }
    card.appendChild(el("details", { cls: "raw-line" },
      el("summary", null, el("span", { text: U["root.raw"] + " " }), el("span", { cls: "proof", text: req.ref })),
      el("pre", { cls: "raw", text: req.raw }),
      copyButton(req.raw)));
    return card;
  }

  // PHP on one line, with the spots that matter marked: in the vulnerable line, variables
  // put straight into the query text; in the fix, the placeholders that replace them.
  function phpLine(line, kind) {
    var out = el("code"), buf = "", quote = null, i = 0;
    function flush() { if (buf) { out.appendChild(document.createTextNode(buf)); buf = ""; } }
    function put(text, cls) { flush(); out.appendChild(el("span", { cls: cls, text: text })); }
    while (i < line.length) {
      var ch = line.charAt(i), rest = line.slice(i), v;
      if (quote) {
        if (ch === "\\") { buf += line.substr(i, 2); i += 2; continue; }
        if (ch === quote) { quote = null; buf += ch; i++; continue; }
        if (kind === "bad" && quote === '"' && (v = /^\{?\$[A-Za-z_]\w*(?:\[[^\]]*\]|->\w+)?\}?/.exec(rest))) {
          put(v[0], "taint"); i += v[0].length; continue;
        }
        if (kind === "fix" && ch === "?") { put("?", "hole"); i++; continue; }
        buf += ch; i++; continue;
      }
      if (ch === '"' || ch === "'") { quote = ch; buf += ch; i++; continue; }
      if (kind === "bad" && ch === "$" && (v = /^\$[A-Za-z_]\w*(?:\[[^\]]*\])?/.exec(rest))) {
        var before = line.slice(0, i).replace(/\s+$/, "").slice(-1);
        var after = line.slice(i + v[0].length).replace(/^\s+/, "").charAt(0);
        if (/^\$_(?:GET|POST|REQUEST|COOKIE)\b/.test(v[0]) || before === "." || after === ".") {
          put(v[0], "taint"); i += v[0].length; continue;
        }
      }
      buf += ch; i++;
    }
    flush();
    return out;
  }

  function flowStep(label, value) {
    return el("li", null, el("span", { cls: "flow-l", text: label }),
      value ? el("span", { cls: "mono flow-v", text: value }) : null);
  }

  function codeCard(c) {
    var card = el("div", { cls: "code-card" });
    card.appendChild(el("div", { cls: "code-head" },
      el("span", { cls: "mono code-loc", text: c.file + ":" + c.line }),
      conf(c.conf, fmt(U["chain.strength"], { level: c.confLabel }))));
    card.appendChild(el("ol", { cls: "flow", "aria-label": U["flow.title"] },
      flowStep(U["flow.input"], c.sources.join(", ")),
      flowStep(fmt(U["flow.build"], { line: c.line }), null),
      c.sinkLine ? flowStep(fmt(U["flow.run"], { line: c.sinkLine }), c.sink) : null));
    var diff = el("div", { cls: "diff", role: "group", "aria-label": U["diff.title"] });
    diff.appendChild(el("div", { cls: "dl-row del" },
      el("span", { cls: "dl-n", text: String(c.line) }), el("span", { cls: "dl-s", text: "−", "aria-label": U["diff.now"] }),
      phpLine(c.snippet, "bad")));
    c.fix.forEach(function (line) {
      diff.appendChild(el("div", { cls: "dl-row add" },
        el("span", { cls: "dl-n" }), el("span", { cls: "dl-s", text: "+", "aria-label": U["diff.fix"] }),
        phpLine(line, "fix")));
    });
    card.appendChild(diff);
    card.appendChild(el("div", { cls: "code-foot" },
      el("span", { cls: "muted", text: c.fix.length ? U["diff.legend"] : U["diff.legend_nofix"] }),
      c.fix.length ? copyButton(c.fix.join("\n"), U["diff.copy"]) : null));
    if (!c.verified) card.appendChild(el("p", { cls: "warn", text: U["code.unverified"] }));
    var dl = el("dl", { cls: "kv" });
    pairs(dl, U["code.why"], c.why);
    pairs(dl, U["code.proof"], el("span", { cls: "proof", text: c.ref }));
    card.appendChild(dl);
    return card;
  }

  function buildRoot(s) {
    var r = X.root, v = D.verdict.root, e = byN[r.n];
    var box = el("div", { cls: "doc rc" }, el("h2", { text: s.title }));
    box.appendChild(el("div", { cls: "rc-head" },
      el("p", { cls: "rc-vuln", text: v.vuln }),
      el("p", { cls: "rc-event", text: e.text }),
      el("div", { cls: "rc-meta" },
        el("button", { cls: "link", text: fmt(U["root.open"], { n: no(r.n) }), onclick: function () { openEvent(r.n); } }),
        el("span", { text: v.day + " " + v.clock + " " + D.zoneShort }),
        v.actor ? el("button", { cls: "link mono", title: U["ioc.find_actor"], text: v.actor,
          onclick: function () { lookUp(v.actor, true); } }) : null,
        conf(v.conf, fmt(U["chain.strength"], { level: v.confLabel })))));

    var grid = el("div", { cls: "rc-grid" });
    var left = el("div", { cls: "rc-col" }), right = el("div", { cls: "rc-col" });
    if (r.request) {
      left.appendChild(el("h3", { text: U["root.request"] }));
      left.appendChild(requestCard(r.request));
    }
    left.appendChild(el("h3", { text: U["root.why"] }));
    var why = el("ol", { cls: "why" });
    r.reasons.forEach(function (t) { why.appendChild(el("li", { text: t })); });
    left.appendChild(why);
    if (r.alts.length) {
      left.appendChild(el("h3", { text: U["root.alts"] }));
      var alts = el("ul", { cls: "alts" });
      r.alts.forEach(function (a) { alts.appendChild(el("li", null, eventLink(a.n), " " + a.text)); });
      left.appendChild(alts);
    }

    right.appendChild(el("h3", { text: U["root.code"] }));
    r.code.forEach(function (c) { right.appendChild(codeCard(c)); });
    if (r.codeNone) right.appendChild(el("p", { cls: "muted", text: U["code.none"] }));
    if (!r.code.length && !r.codeNone && !r.analyzed.length && !r.noContent.length) right.appendChild(el("p", { cls: "muted", text: U["code.not_run"] }));
    if (r.analyzed.length || r.included.length) {
      var scope = el("dl", { cls: "kv scope" });
      if (r.analyzed.length) pairs(scope, U["code.analyzed"], el("span", { cls: "mono", text: r.analyzed.join("\n") }));
      if (r.included.length) pairs(scope, U["code.included"], el("span", { cls: "mono", text: r.included.join("\n") }));
      right.appendChild(scope);
    }
    if (r.noContent.length) {
      right.appendChild(el("p", { cls: "warn", text: U["code.no_content"] }));
      var nc = el("ul", { cls: "mono plain" });
      r.noContent.forEach(function (p) { nc.appendChild(el("li", { text: p })); });
      right.appendChild(nc);
    }
    grid.appendChild(left);
    grid.appendChild(right);
    box.appendChild(grid);
    return box;
  }

  // --- files ------------------------------------------------------------------------------

  function fileCard(f) {
    var card = el("article", { cls: "fcard" });
    card.appendChild(el("div", { cls: "f-head" },
      el("h3", { cls: "mono f-path", text: f.path }),
      el("span", { cls: "f-status", text: f.status })));
    if (f.findings.length) {
      var ul = el("ul", { cls: "f-find" });
      f.findings.forEach(function (x) {
        ul.appendChild(el("li", null, el("span", { text: x.text }),
          el("span", { cls: "mono rule", text: x.rule }),
          conf(x.conf, fmt(U["chain.strength"], { level: x.confLabel }))));
      });
      card.appendChild(ul);
    }
    var dl = el("dl", { cls: "kv" });
    pairs(dl, "SHA-256", el("span", { cls: "hash" }, el("span", { cls: "mono", text: f.sha256 }), copyButton(f.sha256)));
    pairs(dl, U["file.size"], f.size);
    pairs(dl, U["file.status"], f.status);
    var times = el("span", { cls: "times" });
    f.times.forEach(function (t) {
      times.appendChild(el("span", null, el("span", { cls: "t-name", text: t.name }), " " + t.time));
    });
    pairs(dl, U["file.times"], f.times.length ? times : U["file.no_times"]);
    pairs(dl, U["file.ts_source"], f.tsSource);
    if (f.urls.length) pairs(dl, U["file.urls"], el("span", { cls: "mono", text: f.urls.join("\n") }));
    if (f.fim.length) pairs(dl, U["file.fim"], f.fim.join("\n"));
    card.appendChild(dl);
    card.appendChild(fileLinks(f.path, f.events));
    return card;
  }

  function fileLinks(path, list) {
    return el("div", { cls: "f-links" },
      list.length ? el("span", { cls: "muted", text: U["file.events"] }) : null,
      list.length ? eventLinks(list) : null,
      el("button", { cls: "link", text: U["file.search"], onclick: function () { lookUp(path, false); } }));
  }

  function buildFiles(s) {
    var box = el("div", { cls: "doc" }, el("h2", { text: s.title }));
    X.files.files.forEach(function (f) { box.appendChild(fileCard(f)); });
    var lo = X.files.logOnly;
    if (lo) {
      box.appendChild(el("h3", { text: lo.title }));
      box.appendChild(el("p", { cls: "muted", text: lo.note }));
      lo.items.forEach(function (it) {
        box.appendChild(el("article", { cls: "fcard slim" },
          el("div", { cls: "f-head" }, el("h3", { cls: "mono f-path", text: it.path })),
          fileLinks(it.path, it.events)));
      });
    }
    return box;
  }

  // --- IOCs -------------------------------------------------------------------------------

  function buildIocs(s) {
    var box = el("div", { cls: "doc" }, el("h2", { text: s.title }),
      el("p", { cls: "muted lead", text: U["ioc.lead"] }));
    var all = [];
    X.iocs.forEach(function (g) {
      all = all.concat(g.values);
      var list = el("ul", { cls: "ioc-list" });
      g.values.forEach(function (v) {
        var asActor = g.key === "ips";
        list.appendChild(el("li", null,
          el("button", { cls: "ioc-v mono", title: asActor ? U["ioc.find_actor"] : U["ioc.find"], text: v,
            onclick: function () { lookUp(v, asActor); } }),
          copyButton(v)));
      });
      box.appendChild(el("section", { cls: "ioc-group" },
        el("div", { cls: "ioc-head" },
          el("h3", null, el("span", { text: g.label }), el("span", { cls: "tab-n", text: String(g.values.length) })),
          copyButton(g.values.join("\n"), U["ioc.copy_group"])),
        list));
    });
    box.insertBefore(el("div", { cls: "ioc-all" }, copyButton(all.join("\n"), U["ioc.copy_all"])), box.children[2]);
    return box;
  }

  // --- evidence gaps ----------------------------------------------------------------------

  function buildGaps(s) {
    var box = el("div", { cls: "doc" }, el("h2", { text: s.title }),
      el("p", { cls: "muted lead", text: U["gaps.lead"] }));
    var body = el("tbody");
    X.gaps.rows.forEach(function (g) {
      var when = g.when ? el("span", null, el("span", { text: g.when }),
        g.from !== null ? el("button", { cls: "link block", text: U["gaps.show"], onclick: function () { zoomTo(g.from, g.to); } }) : null)
        : el("span", { cls: "muted", text: "-" });
      body.appendChild(el("tr", null,
        el("td", null, el("span", { cls: "gap-id", text: g.label })),
        el("td", { text: g.kind }),
        el("td", null, when),
        el("td", null, el("span", { text: g.detail }), g.source ? el("span", { cls: "mono src", text: g.source }) : null),
        el("td", null, g.affects.length ? eventLinks(g.affects) : el("span", { cls: "muted", text: "-" }))));
    });
    box.appendChild(el("div", { cls: "tw" }, el("table", { cls: "gaps" },
      el("thead", null, el("tr", null,
        el("th", { text: U["gaps.id"] }), el("th", { text: U["gaps.kind"] }), el("th", { text: U["gaps.when"] }),
        el("th", { text: U["gaps.detail"] }), el("th", { text: U["gaps.affects"] }))),
      body)));
    if (X.gaps.more) box.appendChild(el("p", { cls: "muted", text: X.gaps.more }));
    return box;
  }

  // --- actions: a checklist the analyst ticks off -------------------------------------------

  function loadTicks() {
    try { return JSON.parse(window.localStorage.getItem(STORE) || "{}") || {}; } catch (_) { return {}; }
  }

  function saveTicks(ticks) {
    try { window.localStorage.setItem(STORE, JSON.stringify(ticks)); } catch (_) { /* private mode */ }
  }

  function buildActions(s) {
    var ticks = loadTicks(), total = 0, boxes = [];
    var box = el("div", { cls: "doc" }, el("h2", { text: s.title }));
    var bar = el("span", { cls: "bar-fill" });
    var progress = el("div", { cls: "progress" },
      el("span", { cls: "bar" }, bar), el("span", { cls: "p-text", "aria-live": "polite" }));
    box.appendChild(progress);
    X.actions.forEach(function (phase) {
      var count = el("span", { cls: "tab-n" });
      var list = el("ul", { cls: "checks" });
      phase.items.forEach(function (text, i) {
        var id = phase.phase + ":" + i;
        var input = el("input", { type: "checkbox", id: "act-" + id.replace(":", "-") });
        input.checked = Boolean(ticks[id]);
        input.addEventListener("change", function () {
          if (input.checked) ticks[id] = true; else delete ticks[id];
          saveTicks(ticks);
          update();
        });
        boxes.push({ input: input, phase: phase.phase });
        list.appendChild(el("li", null, el("label", { "for": "act-" + id.replace(":", "-") }, input, el("span", { text: text }))));
        total++;
      });
      phase.count = count;
      box.appendChild(el("section", { cls: "phase" }, el("h3", null, el("span", { text: phase.title }), count), list));
    });
    box.appendChild(el("p", { cls: "muted note", text: U["actions.saved"] }));

    function update() {
      var done = 0, per = {};
      boxes.forEach(function (b) {
        per[b.phase] = per[b.phase] || [0, 0];
        per[b.phase][1]++;
        if (b.input.checked) { done++; per[b.phase][0]++; }
        b.input.parentNode.parentNode.classList.toggle("done", b.input.checked);
      });
      X.actions.forEach(function (p) { p.count.textContent = per[p.phase][0] + "/" + per[p.phase][1]; });
      bar.style.width = (total ? Math.round(done / total * 100) : 0) + "%";
      progress.lastChild.textContent = fmt(U["actions.progress"], { done: done, total: total });
      if (badges.actions) badges.actions.textContent = String(total - done);
    }
    update();
    return box;
  }

  // --- the full report, in its own tab ------------------------------------------------------

  function buildReport() {
    document.body.classList.add("report-mode");
    app.appendChild(el("div", { cls: "rbar" },
      el("span", { cls: "brand", text: "webforensics" }),
      el("span", { cls: "case", text: U["meta.case"] + " " + D.caseId }),
      el("span", { cls: "rbar-r" },
        el("button", { cls: "btn", text: U["report.print"], onclick: function () { window.print(); } }),
        el("button", { cls: "link", text: U["report.back"], onclick: function () {
          history.replaceState(null, "", location.pathname + location.search);
          location.reload();
        } }))));
    var page = el("main", { cls: "report" },
      el("h1", { text: D.title }), el("p", { cls: "sub", text: D.subtitle }));
    var toc = el("ol");
    D.doc.forEach(function (s) {
      var target = "r-" + s.anchor;
      toc.appendChild(el("li", null, el("a", { href: "#laporan", text: s.title, onclick: function (ev) {
        ev.preventDefault();
        document.getElementById(target).scrollIntoView({ block: "start" });
      } })));
    });
    page.appendChild(el("nav", { cls: "toc", "aria-label": U["report.toc"] }, toc));
    D.doc.forEach(function (s) {
      var node = el("section", { id: "r-" + s.anchor }, el("h2", { text: s.title }));
      s.blocks.forEach(function (b) { node.appendChild(docBlock(b)); });
      page.appendChild(node);
    });
    page.appendChild(el("p", { cls: "muted r-foot", text: U.generated_by }));
    app.appendChild(page);
    window.addEventListener("hashchange", function () {
      if (location.hash !== "#laporan") location.reload();
    });
  }

  // --- the report's own text --------------------------------------------------------------

  function docSection(section) {
    var node = el("div", { cls: "doc" }, el("h2", { text: section.title }));
    section.blocks.forEach(function (b) { node.appendChild(docBlock(b)); });
    return node;
  }

  function docBlock(b) {
    if (b.t === "p") return el("p", { text: b.text });
    if (b.t === "h") return el("h3", { text: b.text });
    if (b.t === "ul") {
      var ul = el("ul");
      b.items.forEach(function (t) { ul.appendChild(el("li", { text: t })); });
      return ul;
    }
    if (b.t === "code") return el("pre", { text: b.lines.join("\n") });
    if (b.t === "dl") {
      var dl = el("dl", { cls: "kv" });
      b.pairs.forEach(function (p) { pairs(dl, p[0], p[1]); });
      return dl;
    }
    if (b.t === "table") {
      var head = el("tr");
      b.headers.forEach(function (h) { head.appendChild(el("th", { text: h })); });
      var body = el("tbody");
      b.rows.forEach(function (row, i) {
        var tr = el("tr", { cls: b.hl.indexOf(i) >= 0 ? "hl" : null });
        row.forEach(function (c) {
          if (c.mark && c.mark !== "root") tr.appendChild(el("td", null, conf(c.mark, c.text)));
          else tr.appendChild(el("td", { cls: c.mark === "root" ? "mark-root" : null, text: c.text }));
        });
        body.appendChild(tr);
      });
      return el("div", { cls: "tw" }, el("table", null, el("thead", null, head), body));
    }
    return el("p", { text: "" });
  }

  // --- timeline: chart, register and inspector -------------------------------------------

  var svgHost, resetBtn, listEl, countEl, moreBox, inspector, searchBox, marks = {}, rows = {};

  function buildTimeline(panel) {
    resetBtn = el("button", { cls: "link", text: U["chart.reset"], hidden: true,
      onclick: function () { state.zoom = null; refresh(); } });
    svgHost = el("div", { cls: "chart" });

    searchBox = el("input", {
      type: "search", placeholder: U["filter.search"], "aria-label": U["filter.search"],
      oninput: function () { state.q = searchBox.value.trim().toLowerCase(); state.limit = PAGE; refresh(); }
    });
    var actor = el("select", { "aria-label": U["filter.actor"],
      onchange: function () { state.actor = actor.value; state.limit = PAGE; refresh(); }
    }, el("option", { value: "*", text: U["filter.actor"] }));
    actorList().forEach(function (a) { actor.appendChild(el("option", { value: a, text: a || U["chart.files"] })); });
    var storyBox = el("input", { type: "checkbox", id: "story-only",
      onchange: function () { state.story = storyBox.checked; state.limit = PAGE; refresh(); } });
    countEl = el("span", { cls: "count", "aria-live": "polite" });
    var kinds = el("div", { cls: "kinds" });
    present().forEach(function (c) {
      var b = el("button", { cls: "kind", "aria-pressed": "true", title: c.label,
        onclick: function () {
          state.cats[c.id] = !state.cats[c.id];
          b.setAttribute("aria-pressed", state.cats[c.id] ? "true" : "false");
          state.limit = PAGE; refresh();
        } }, glyph(c.id), el("span", { text: c.label }));
      kinds.appendChild(b);
    });

    listEl = el("tbody");
    moreBox = el("div", { cls: "more" });
    inspector = el("aside", { cls: "inspector", "aria-live": "polite" });
    var table = el("table", { cls: "register" },
      el("thead", null, el("tr", null,
        el("th", { cls: "c-n", text: U["col.n"] }),
        el("th", { cls: "c-t", text: U["col.time"] + " " + D.zoneShort }),
        el("th", { cls: "c-a", text: U["col.actor"] }),
        el("th", { text: U["col.event"] }),
        el("th", { cls: "c-c", text: U["col.confidence"] }))),
      listEl);

    panel.appendChild(el("div", { cls: "chart-box" },
      el("div", { cls: "chart-head" }, el("h2", { text: U["chart.title"] }),
        el("span", { cls: "hint", text: U["chart.hint"] }), resetBtn),
      svgHost));
    panel.appendChild(el("div", { cls: "filters" }, searchBox, actor, kinds,
      el("label", { cls: "toggle", "for": "story-only" }, storyBox, U["filter.story"]), countEl));
    panel.appendChild(el("div", { cls: "work" },
      el("div", { cls: "reg-box" }, table, moreBox), inspector));
    renderInspector();
    renderList();

    if (window.ResizeObserver) {
      var pending = null;
      new ResizeObserver(function () {
        if (pending) cancelAnimationFrame(pending);
        pending = requestAnimationFrame(function () { if (state.tab === "timeline") drawChart(); });
      }).observe(svgHost);
    }
  }

  function present() {
    return D.categories.filter(function (c) {
      return events.some(function (e) { return e.cat === c.id; });
    });
  }

  function actorList() {
    var seen = {}, out = [];
    D.lanes.concat(events.map(function (e) { return e.actor; })).forEach(function (a) {
      if (!seen[a]) { seen[a] = true; out.push(a); }
    });
    return out;
  }

  function matches(e) {
    if (!state.cats[e.cat]) return false;
    if (state.actor !== "*" && e.actor !== state.actor) return false;
    if (state.story && !(e.story || e.root)) return false;
    if (state.zoom && (e.ms < state.zoom[0] || e.ms > state.zoom[1])) return false;
    if (state.q && e.search.indexOf(state.q) < 0) return false;
    return true;
  }

  function refresh() {
    resetBtn.hidden = !state.zoom;
    drawChart();
    renderList();
  }

  // One SVG mark per event: the shape says what kind of event it is.
  function mark(cat, x, y, root) {
    var r = root ? 5.5 : 4.5, node;
    if (cat === "recon") node = sv("circle", { cx: x, cy: y, r: r - 0.5 });
    else if (cat === "exploit") node = sv("polygon", { points: [x, y - r - 1, x + r + 1, y + r, x - r - 1, y + r].join(" ") });
    else if (cat === "login") node = sv("polygon", { points: [x, y - r - 1, x + r + 1, y, x, y + r + 1, x - r - 1, y].join(" ") });
    else if (cat === "write") node = sv("rect", { x: x - r + 0.5, y: y - r + 0.5, width: 2 * r - 1, height: 2 * r - 1 });
    else if (cat === "file") node = sv("rect", { x: x - r + 1, y: y - r + 1, width: 2 * r - 2, height: 2 * r - 2 });
    else if (cat === "use") node = sv("circle", { cx: x, cy: y, r: r - 0.5 });
    else node = sv("circle", { cx: x, cy: y, r: 2 });
    return node;
  }

  function drawChart() {
    if (!svgHost || state.tab !== "timeline") return;
    if (!events.length) {
      svgHost.textContent = "";
      svgHost.appendChild(el("p", { cls: "hint", text: U["chart.empty"] }));
      return;
    }
    var width = Math.max(320, svgHost.clientWidth || 800);
    var left = width < 560 ? 92 : 132, right = 12, top = 18, laneH = 24, axisH = 22;
    var lanes = D.lanes.slice();
    var othersLane = hasOthers ? lanes.length : -1;
    var laneCount = lanes.length + (hasOthers ? 1 : 0);
    var plotH = laneCount * laneH, height = top + plotH + axisH;
    var shown = events.filter(matches);
    var lo = state.zoom ? state.zoom[0] : events[0].ms;
    var hi = state.zoom ? state.zoom[1] : events[events.length - 1].ms;
    if (hi - lo < 10000) { var mid = (hi + lo) / 2; lo = mid - 5000; hi = mid + 5000; }
    var pad = state.zoom ? 0 : (hi - lo) * 0.03;
    lo -= pad; hi += pad;
    var plotW = width - left - right;
    function x(ms) { return left + (ms - lo) / (hi - lo) * plotW; }

    var svg = sv("svg", { viewBox: "0 0 " + width + " " + height, height: height, role: "img",
      "aria-label": U["chart.title"] });
    var defs = sv("defs", {});
    var hatch = sv("pattern", { id: "hatch", patternUnits: "userSpaceOnUse", width: 5, height: 5,
      patternTransform: "rotate(45)" });
    hatch.appendChild(sv("line", { "class": "hatchline", x1: 0, y1: 0, x2: 0, y2: 5 }));
    defs.appendChild(hatch);
    svg.appendChild(defs);

    D.gaps.forEach(function (g) {
      if (g.to < lo || g.from > hi) return;
      var x0 = x(Math.max(g.from, lo)), x1 = x(Math.min(g.to, hi));
      var band = sv("rect", { "class": "gapband", x: x0, y: top, width: Math.max(2, x1 - x0),
        height: plotH, fill: "url(#hatch)" });
      band.appendChild(titleNode(g.label + " · " + g.kind));
      svg.appendChild(band);
      if (x1 - x0 > 18) {
        var gl = sv("text", { "class": "gaplabel", x: x0 + 2, y: top - 5 });
        gl.textContent = g.label;
        svg.appendChild(gl);
      }
    });
    ticks(lo, hi).forEach(function (t) {
      var tx = x(t.ms);
      svg.appendChild(sv("line", { "class": "tick", x1: tx, x2: tx, y1: top, y2: top + plotH + 3 }));
      var tl = sv("text", { "class": "axis", x: tx, y: top + plotH + 15, "text-anchor": "middle" });
      tl.textContent = t.label;
      svg.appendChild(tl);
    });
    for (var i = 0; i < laneCount; i++) {
      var y = top + i * laneH + laneH / 2;
      svg.appendChild(sv("line", { "class": "base", x1: left, x2: width - right, y1: y, y2: y }));
      var name = i === othersLane ? U["chart.others"] : (lanes[i] || U["chart.files"]);
      // An address is evidence (monospace); "file evidence" and "other actors" are labels.
      var isAddress = i !== othersLane && Boolean(lanes[i]);
      var label = sv("text", { "class": "lane" + (isAddress ? " addr" : "") + (attacker[lanes[i]] ? " att" : ""), x: left - 8,
        y: y + 4, "text-anchor": "end" });
      label.textContent = name.length > 17 ? name.slice(0, 16) + "…" : name;
      label.appendChild(titleNode(name));
      svg.appendChild(label);
    }

    var root = events.filter(function (e) { return e.root; })[0];
    if (root && root.ms >= lo && root.ms <= hi && matches(root)) {
      var rx = x(root.ms);
      svg.appendChild(sv("line", { "class": "rootline", x1: rx, x2: rx, y1: top - 3, y2: top + plotH }));
      var tag = sv("text", { "class": "roottag", x: Math.min(rx + 4, width - right - 60), y: top - 5 });
      tag.textContent = U["chart.root"] + " " + no(root.n);
      svg.appendChild(tag);
    }

    var brush = sv("rect", { "class": "brush", x: 0, y: top, width: 0, height: plotH, visibility: "hidden" });
    svg.appendChild(brush);
    marks = {};
    shown.forEach(function (e) {
      var lane = e.actor in laneOf ? laneOf[e.actor] : othersLane;
      var node = mark(e.cat, x(e.ms), top + lane * laneH + laneH / 2, e.root);
      node.setAttribute("class", "ev k-" + e.cat + (e.root ? " is-root" : "") + (state.sel === e.n ? " sel" : ""));
      node.appendChild(titleNode(no(e.n) + " " + e.clock + " · " + (e.actor || U["chart.files"]) + "\n" + e.text));
      node.addEventListener("click", function (ev) { ev.stopPropagation(); select(e.n, true); });
      marks[e.n] = node;
      svg.appendChild(node);
    });

    // Drag across the chart to zoom into that time range.
    var start = null;
    function px(ev) {
      var r = svg.getBoundingClientRect();
      return (ev.clientX - r.left) * (width / r.width);
    }
    svg.addEventListener("pointerdown", function (ev) {
      if (ev.target.getAttribute && /\bev\b/.test(ev.target.getAttribute("class") || "")) return;
      var p = px(ev);
      if (p < left || p > width - right) return;
      start = p;
      svg.setPointerCapture(ev.pointerId);
      brush.setAttribute("visibility", "visible");
      brush.setAttribute("x", p); brush.setAttribute("width", 0);
    });
    svg.addEventListener("pointermove", function (ev) {
      if (start === null) return;
      var p = Math.min(Math.max(px(ev), left), width - right);
      brush.setAttribute("x", Math.min(start, p));
      brush.setAttribute("width", Math.abs(p - start));
    });
    svg.addEventListener("pointerup", function (ev) {
      if (start === null) return;
      var p = Math.min(Math.max(px(ev), left), width - right);
      var a = Math.min(start, p), b = Math.max(start, p);
      start = null;
      brush.setAttribute("visibility", "hidden");
      if (b - a < 6) return;
      function t(v) { return lo + (v - left) / plotW * (hi - lo); }
      state.zoom = [t(a), t(b)];
      state.limit = PAGE;
      refresh();
    });

    svgHost.textContent = "";
    svgHost.appendChild(svg);
  }

  var STEPS = [1, 5, 15, 30, 60, 300, 900, 1800, 3600, 10800, 21600, 43200, 86400, 604800]
    .map(function (s) { return s * 1000; });

  function ticks(lo, hi) {
    var span = hi - lo, stepMs = STEPS[STEPS.length - 1];
    for (var i = 0; i < STEPS.length; i++) { if (span / STEPS[i] <= 6) { stepMs = STEPS[i]; break; } }
    var off = D.offsetMin * 60000, out = [];
    var first = Math.ceil((lo + off) / stepMs) * stepMs - off;
    var multiDay = span > 86400000;
    for (var ms = first; ms <= hi; ms += stepMs) {
      var d = new Date(ms + off);
      var hm = pad2(d.getUTCHours()) + ":" + pad2(d.getUTCMinutes());
      if (stepMs < 60000) hm += ":" + pad2(d.getUTCSeconds());
      var label = multiDay ? pad2(d.getUTCDate()) + "/" + pad2(d.getUTCMonth() + 1) + (stepMs < 86400000 ? " " + hm : "") : hm;
      out.push({ ms: ms, label: label });
    }
    return out;
  }

  function pad2(n) { return (n < 10 ? "0" : "") + n; }

  // Register: bursts from one actor collapse into one row until opened.
  function visibleRows() {
    var out = [], seenRun = {};
    events.forEach(function (e) {
      if (!matches(e)) return;
      if (e.run === null || state.open[e.run]) { out.push({ e: e, sub: e.run !== null }); return; }
      if (seenRun[e.run]) return;
      seenRun[e.run] = true;
      out.push({ run: e.run, e: e });
    });
    return out;
  }

  function renderList() {
    var all = visibleRows();
    var total = events.filter(matches).length;
    countEl.textContent = fmt(U["filter.count"], { shown: total, total: events.length });
    listEl.textContent = "";
    rows = {};
    if (!all.length) listEl.appendChild(el("tr", { cls: "empty" }, el("td", { colspan: "5", text: U["filter.none"] })));
    var openedRun = {}, day = null;
    all.slice(0, state.limit).forEach(function (r) {
      if (r.e.day !== day) {
        day = r.e.day;
        listEl.appendChild(el("tr", { cls: "day" }, el("td", { colspan: "5", text: day })));
      }
      if (r.run !== undefined) { listEl.appendChild(runRow(r.run, false)); return; }
      if (r.sub && !openedRun[r.e.run]) { openedRun[r.e.run] = true; listEl.appendChild(runRow(r.e.run, true)); }
      listEl.appendChild(eventRow(r.e, r.sub));
    });
    moreBox.textContent = "";
    if (all.length > state.limit) {
      moreBox.appendChild(el("button", { cls: "link",
        text: fmt(U["filter.more"], { count: Math.min(PAGE, all.length - state.limit) }),
        onclick: function () { state.limit += PAGE; renderList(); } }));
    }
  }

  function runRow(id, opened) {
    var run = D.runs[id], first = byN[run.first];
    var toggle = function () { state.open[id] = !state.open[id]; renderList(); };
    return el("tr", {
      cls: "run", tabindex: "0", role: "button", "aria-expanded": opened ? "true" : "false",
      onclick: toggle,
      onkeydown: function (ev) { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggle(); } }
    },
      el("td", { cls: "c-n", text: no(run.first) }),
      el("td", { cls: "c-t", text: run.clock }),
      el("td", { cls: "c-a mono", text: first.actor || D.labels.noActor }),
      el("td", null, glyph(first.cat), el("span", { text: run.text + " " }),
        el("span", { cls: "link", text: opened ? U["run.collapse"] : fmt(U["run.expand"], { count: run.count }) })),
      el("td"));
  }

  function eventRow(e, sub) {
    var cls = [sub ? "sub" : "", e.root ? "root" : "", state.sel === e.n ? "sel" : ""].join(" ").trim();
    var tr = el("tr", {
      cls: cls || null, tabindex: "0", "data-n": String(e.n),
      onclick: function () { select(e.n, false); },
      onkeydown: function (ev) {
        if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); select(e.n, false); }
      }
    },
      el("td", { cls: "c-n", text: no(e.n) }),
      el("td", { cls: "c-t", text: e.clock }),
      el("td", { cls: "c-a mono", text: e.actor || D.labels.noActor }),
      el("td", null, glyph(e.cat), e.root ? el("span", { cls: "flag", text: D.labels.rootMarker }) : null, e.text),
      el("td", { cls: "c-c" }, conf(e.conf, e.confLabel)));
    rows[e.n] = tr;
    return tr;
  }

  // j / k: the next or previous event that is listed.
  function step(dir) {
    var list = visibleRows().filter(function (r) { return r.run === undefined; }).map(function (r) { return r.e.n; });
    if (!list.length) return;
    var i = state.sel === null ? (dir > 0 ? -1 : list.length) : list.indexOf(state.sel);
    var next = list[Math.min(list.length - 1, Math.max(0, i + dir))];
    select(next, true);
  }

  // Selecting from the chart or the trace may need to open a burst, clear filters that hide
  // the event, or show more rows before the row exists.
  function select(n, reveal) {
    var e = byN[n];
    if (!e) return;
    state.sel = n;
    if (reveal) {
      if (!matches(e)) {
        state.q = ""; state.actor = "*"; state.story = false; state.zoom = null;
        D.categories.forEach(function (c) { state.cats[c.id] = true; });
        syncFilterControls();
        drawChart();
      }
      if (e.run !== null) state.open[e.run] = true;
      var idx = visibleRows().findIndex(function (r) { return r.e === e && r.run === undefined; });
      if (idx >= state.limit) state.limit = Math.ceil((idx + 1) / PAGE) * PAGE;
    }
    renderList();
    for (var k in marks) {
      var m = marks[k], c = m.getAttribute("class").replace(/\s*\bsel\b/, "");
      m.setAttribute("class", Number(k) === n ? c + " sel" : c);
    }
    renderInspector();
    document.body.classList.add("inspecting");
    if (location.hash !== "#timeline:" + n) history.replaceState(null, "", "#timeline:" + n);
    if (rows[n] && reveal) rows[n].scrollIntoView({ block: "nearest" });
  }

  function syncFilterControls() {
    var panel = panels.timeline;
    searchBox.value = "";
    panel.querySelector("select").value = "*";
    panel.querySelector("#story-only").checked = false;
    Array.prototype.forEach.call(panel.querySelectorAll(".kind"), function (c) {
      c.setAttribute("aria-pressed", "true");
    });
    resetBtn.hidden = true;
  }

  // --- inspector: the event, and each cited log line taken apart -------------------------

  function dissect(line) {
    var m = COMBINED.exec(line);
    if (!m) return null;
    var parts = [], pos = 0;
    function take(text, key) {
      var at = line.indexOf(text, pos);
      if (at < 0) return;
      if (at > pos) parts.push({ text: line.slice(pos, at) });
      parts.push({ text: text, key: key });
      pos = at + text.length;
    }
    var req = m[5], sp = req.indexOf(" "), method = sp > 0 ? req.slice(0, sp) : req;
    var rest = sp > 0 ? req.slice(sp + 1) : "", end = rest.lastIndexOf(" HTTP/");
    var target = end >= 0 ? rest.slice(0, end) : rest;
    var q = target.indexOf("?"), path = q >= 0 ? target.slice(0, q) : target;
    var query = q >= 0 ? target.slice(q + 1) : "";
    take(m[1], "client"); take(m[4], "time");
    if (method) take(method, "method");
    if (path) take(path, "path");
    if (query) take(query, "query");
    take(m[6], "status"); take(m[7], "bytes");
    if (m[8] && m[8] !== "-") take(m[8], "referer");
    if (m[9]) take(m[9], "agent");
    if (m[10]) take(m[10], "forwarded");
    if (pos < line.length) parts.push({ text: line.slice(pos) });
    var fields = [["client", m[1]], ["time", m[4]], ["method", method], ["path", path],
      ["query", query], ["status", m[6]], ["bytes", m[7]], ["referer", m[8] === "-" ? "" : m[8]],
      ["agent", m[9]], ["forwarded", m[10] || ""]].filter(function (f) { return f[1]; });
    return { parts: parts, fields: fields };
  }

  function evidence(c) {
    var ex = c.ex || "", parsed = dissect(ex);
    var box = el("div", { cls: "ev-cite" }, el("div", { cls: "ev-ref" }, el("span", { cls: "mono", text: c.ref }), copyButton(ex)));
    if (!parsed) { box.appendChild(el("pre", { cls: "raw", text: ex })); return box; }
    var raw = el("pre", { cls: "raw" }), spans = {};
    parsed.parts.forEach(function (p) {
      var s = el("span", { cls: p.key ? "seg seg-" + p.key : null, text: p.text });
      if (p.key) spans[p.key] = s;
      raw.appendChild(s);
    });
    var table = el("table", { cls: "fields" });
    parsed.fields.forEach(function (f) {
      var tr = el("tr", {
        onmouseenter: function () { if (spans[f[0]]) spans[f[0]].classList.add("on"); },
        onmouseleave: function () { if (spans[f[0]]) spans[f[0]].classList.remove("on"); }
      }, el("th", { text: U["field." + f[0]] }), el("td", { cls: "mono", text: f[1] }));
      table.appendChild(tr);
    });
    box.appendChild(raw);
    var query = parsed.fields.filter(function (f) { return f[0] === "query"; })[0];
    var params = query ? paramTable(query[1]) : null;
    if (params) {
      box.appendChild(el("div", { cls: "sub-h", text: U["raw.params"] }));
      box.appendChild(params);
    }
    box.appendChild(el("div", { cls: "sub-h", text: U["raw.fields"] }));
    box.appendChild(table);
    return box;
  }

  function renderInspector() {
    inspector.textContent = "";
    var e = state.sel !== null ? byN[state.sel] : null;
    if (!e) { inspector.appendChild(el("p", { cls: "hint", text: U["detail.empty"] })); return; }
    inspector.appendChild(el("div", { cls: "insp-head" },
      el("span", { text: no(e.n) }),
      e.root ? el("span", { cls: "flag", text: U["detail.root"] }) : null,
      el("button", { cls: "link close", text: U["detail.close"],
        onclick: function () { document.body.classList.remove("inspecting"); } })));
    inspector.appendChild(el("p", { cls: "insp-text" }, glyph(e.cat), e.text));
    var dl = el("dl", { cls: "kv" });
    pairs(dl, U["detail.time"], e.day + " " + e.clock + " " + D.zoneShort);
    pairs(dl, U["detail.basis"], e.basis);
    pairs(dl, U["detail.phase"], e.phase);
    pairs(dl, U["detail.actor"], el("span", { cls: "mono", text: e.actor || D.labels.noActor }));
    pairs(dl, U["detail.confidence"], conf(e.conf, e.confLabel));
    inspector.appendChild(dl);
    if (e.notes.length) {
      inspector.appendChild(el("div", { cls: "sub-h", text: U["detail.notes"] }));
      var ul = el("ul", { cls: "notes" });
      e.notes.forEach(function (t) { ul.appendChild(el("li", { text: t })); });
      inspector.appendChild(ul);
    }
    inspector.appendChild(el("div", { cls: "sub-h", text: U["detail.evidence"] }));
    e.cites.forEach(function (i) { inspector.appendChild(evidence(D.cites[i])); });
  }

  route(location.hash.slice(1));
})();
