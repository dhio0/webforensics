"use strict";
(function () {
  // Every string comes from the embedded JSON (often attacker-controlled log text).
  // It is only ever set with textContent or as an attribute value; never as markup.
  var D = JSON.parse(document.getElementById("data").textContent);
  var U = D.ui;
  var SVGNS = "http://www.w3.org/2000/svg";
  var PAGE = 200;
  var DIGITS = Math.max(2, String(D.events.length).length);

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
  var counts = [[stats.events, U["stat.events"]], [stats.files, U["stat.files"]],
    [stats.actors, U["stat.actors"]], [stats.gaps, U["stat.gaps"]]].map(function (c) {
    return c[0] + " " + c[1];
  }).join(" · ");

  app.appendChild(el("header", { cls: "top" },
    el("div", { cls: "top-l" },
      el("span", { cls: "brand", text: "webforensics" }),
      el("span", { cls: "case" }, el("span", { cls: "muted", text: U["meta.case"] + " " }),
        el("span", { cls: "mono", text: D.caseId })),
      el("span", { cls: "verdict" + (bad ? " bad" : ""), role: "status" },
        el("i", { "aria-hidden": "true" }), bad ? U["stamp.compromised"] : U["stamp.clean"])),
    el("div", { cls: "top-r" },
      el("span", { cls: "muted", text: counts }),
      el("span", { cls: "muted" }, U["meta.generated"] + " ", el("span", { cls: "mono", text: D.generated })))));

  var nav = el("nav", { cls: "nav", role: "tablist" });
  app.appendChild(nav);
  var main = el("main", { cls: "page" });
  app.appendChild(main);
  var panels = {};
  D.tabs.forEach(function (tab, i) {
    nav.appendChild(el("button", {
      role: "tab", id: "tab-" + tab.id, "aria-controls": "panel-" + tab.id,
      onclick: function () { showTab(tab.id, true); }
    }, el("span", { cls: "key", text: String(i + 1) }), tab.label));
    var panel = el("section", { role: "tabpanel", id: "panel-" + tab.id, "aria-labelledby": "tab-" + tab.id });
    panel.hidden = true;
    panels[tab.id] = panel;
    main.appendChild(panel);
    if (tab.id === "overview") buildOverview(panel, tab);
    else if (tab.id === "timeline") buildTimeline(panel);
    else tab.sections.forEach(function (s) { panel.appendChild(docSection(s)); });
  });
  app.appendChild(el("footer", { cls: "foot" },
    el("span", { text: U.generated_by }), el("span", { cls: "mono", text: U.keys })));

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
    var m = /^timeline:(\d+)$/.exec(hash);
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

  function buildOverview(panel, tab) {
    var frames = story().slice().reverse();
    var trace = el("ol", { cls: "trace" });
    frames.forEach(function (e) {
      // A file is cited as "path @hash"; the path is already in the text, so show the hash.
      var cite = e.cites.length ? D.cites[e.cites[0]].ref : "", at = cite.lastIndexOf(" @");
      trace.appendChild(el("li", {
        cls: e.root ? "root" : null, tabindex: "0",
        onclick: function () { openEvent(e.n); },
        onkeydown: function (ev) { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); openEvent(e.n); } }
      },
        el("span", { cls: "frame mono", text: no(e.n) }),
        el("span", { cls: "role" }, glyph(e.cat), U["role." + e.cat] || U["role.other"]),
        el("span", { cls: "what" }, e.text,
          e.root ? el("span", { cls: "flag", text: U["trace.root"] }) : null),
        el("span", { cls: "ref mono", title: cite, text: at > 0 ? cite.slice(at + 1) : cite }),
        el("span", { cls: "at mono", text: e.clock })));
    });
    var traceBox = el("div", { cls: "trace-box" },
      el("h2", { text: U["trace.title"] }),
      el("p", { cls: "hint", text: U["trace.hint"] }),
      frames.length ? trace : el("p", { cls: "none", text: U["trace.none"] }));

    var summary = el("div", { cls: "summary" }, el("h2", { text: U["summary.title"] }));
    tab.sections.forEach(function (s) {
      for (var i = 0; i < s.blocks.length && s.blocks[i].t !== "h"; i++) summary.appendChild(docBlock(s.blocks[i]));
    });

    panel.appendChild(el("div", { cls: "overview" },
      el("div", { cls: "ov-main" }, traceBox, summary), facts()));
  }

  function facts() {
    var v = D.verdict, dl = el("dl", { cls: "facts" });
    pairs(dl, U["facts.verdict"], bad ? U["stamp.compromised"] : U["stamp.clean"]);
    if (v.root) {
      var entry = el("a", { href: "#timeline", cls: "mono",
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
      pairs(dl, U["facts.window"], el("span", { cls: "mono", text: a.day + " " + a.clock + "\n" + b.day + " " + b.clock }));
    }
    pairs(dl, U["meta.zone"], D.zone);
    return el("aside", { cls: "ov-side" }, el("h2", { text: U["facts.title"] }), dl);
  }

  function openEvent(n) {
    showTab("timeline", true);
    select(n, true);
  }

  // --- static sections (same content as the HTML report) ---------------------------------

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
    countEl = el("span", { cls: "count mono", "aria-live": "polite" });
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
      var label = sv("text", { "class": "lane" + (attacker[lanes[i]] ? " att" : ""), x: left - 8,
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
      el("td", { cls: "c-n mono", text: no(run.first) }),
      el("td", { cls: "c-t mono", text: run.clock }),
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
      el("td", { cls: "c-n mono", text: no(e.n) }),
      el("td", { cls: "c-t mono", text: e.clock }),
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

  // Combined log format, as the analysis parsed it. Used only to show the line's fields;
  // a line that does not match is shown whole.
  var COMBINED = /^(\S+) (\S+) (\S+) \[([^\]]+)\] "((?:[^"\\]|\\.)*)" (\d{3}) (\d+|-) "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)"(?: "((?:[^"\\]|\\.)*)")?$/;

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
    var copy = el("button", { cls: "link copy", text: U.copy, onclick: function () {
      if (navigator.clipboard) navigator.clipboard.writeText(ex).then(function () {
        copy.textContent = U.copied;
        setTimeout(function () { copy.textContent = U.copy; }, 1200);
      });
    } });
    var box = el("div", { cls: "ev-cite" }, el("div", { cls: "ev-ref" }, el("span", { cls: "mono", text: c.ref }), copy));
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
    box.appendChild(el("div", { cls: "sub-h", text: U["raw.fields"] }));
    box.appendChild(table);
    return box;
  }

  function renderInspector() {
    inspector.textContent = "";
    var e = state.sel !== null ? byN[state.sel] : null;
    if (!e) { inspector.appendChild(el("p", { cls: "hint", text: U["detail.empty"] })); return; }
    inspector.appendChild(el("div", { cls: "insp-head" },
      el("span", { cls: "mono", text: no(e.n) }),
      e.root ? el("span", { cls: "flag", text: U["detail.root"] }) : null,
      el("button", { cls: "link close", text: "Esc", "aria-label": "Esc",
        onclick: function () { document.body.classList.remove("inspecting"); } })));
    inspector.appendChild(el("p", { cls: "insp-text" }, glyph(e.cat), e.text));
    var dl = el("dl", { cls: "kv" });
    pairs(dl, U["detail.time"], el("span", { cls: "mono", text: e.day + " " + e.clock + " " + D.zoneShort }));
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
