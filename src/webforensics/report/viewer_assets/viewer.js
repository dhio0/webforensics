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

  function no(n) {
    var s = String(n);
    while (s.length < DIGITS) s = "0" + s;
    return "#" + s;
  }

  function glyph(cat) { return el("i", { cls: "g g-" + cat, "aria-hidden": "true" }); }

  function meter(conf, label) {
    return el("span", { cls: "meter c-" + conf }, el("i", { "aria-hidden": "true" }), label);
  }

  function field(dl, label, value) {
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

  var state = {
    tab: "overview", sel: null, q: "", actor: "*", story: false, limit: PAGE,
    cats: {}, open: {}, zoom: null
  };
  D.categories.forEach(function (c) { state.cats[c.id] = true; });

  // Motion is decoration: it is skipped entirely when the viewer asks for less of it.
  var REDUCED = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  var POP_LIMIT = 400;  // more marks than this appear at once instead of one by one
  var chartPlayed = false, flowShown = false, spaceView = null;

  // A motion class is always taken off again after its run. If a renderer never plays CSS
  // animations (some screenshot tools, previews), the page still ends up fully visible.
  function playOnce(node, cls, ms) {
    if (REDUCED) return;
    node.classList.remove(cls);
    void node.getBoundingClientRect();
    node.classList.add(cls);
    setTimeout(function () { node.classList.remove(cls); }, ms);
  }

  function css(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  // --- icons: small line drawings, 24x24, stroked with the current colour ---------------

  var ICONS = {
    overview: "M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z",
    timeline: "M3 12h4l3-8 4 16 3-8h4",
    flow: "M6 3v6M6 15v6M6 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6M6 12h6a6 6 0 0 0 6-6V3M18 3l-2 2M18 3l2 2",
    space: "M12 2l9 5v10l-9 5-9-5V7zM12 22V12M21 7l-9 5-9-5",
    root: "M12 3v4M12 17v4M3 12h4M17 12h4M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8",
    files: "M14 3H6v18h12V7zM14 3v4h4M9 13h6M9 17h6",
    iocs: "M12 3l9 16H3zM12 10v4M12 17h.01",
    gaps: "M4 6h4M12 6h4M20 6h0M4 18h4M12 18h4M4 12h16",
    actions: "M9 6h11M9 12h11M9 18h11M4 6l1 1 2-2M4 12l1 1 2-2M4 18l1 1 2-2",
    "case": "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18M12 11v5M12 8h.01",
    events: "M3 12h4l3-8 4 16 3-8h4",
    actors: "M12 4a4 4 0 1 0 0 8 4 4 0 0 0 0-8M4 21a8 8 0 0 1 16 0",
    shield: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"
  };

  function icon(name, cls) {
    var svg = sv("svg", { viewBox: "0 0 24 24", "class": "ic" + (cls ? " " + cls : ""), "aria-hidden": "true" });
    svg.appendChild(sv("path", { d: ICONS[name] || ICONS.overview }));
    return svg;
  }

  // Cards lean a few degrees toward the pointer. Pure decoration: off for reduced motion
  // and for touch, where there is no hover.
  var CAN_TILT = !REDUCED && !!(window.matchMedia && window.matchMedia("(hover: hover)").matches);
  function tilt(node) {
    if (!CAN_TILT) return node;
    node.classList.add("tilt");
    node.addEventListener("pointermove", function (ev) {
      var b = node.getBoundingClientRect();
      var px = (ev.clientX - b.left) / b.width - 0.5, py = (ev.clientY - b.top) / b.height - 0.5;
      node.style.setProperty("--ry", (px * 6).toFixed(2) + "deg");
      node.style.setProperty("--rx", (-py * 6).toFixed(2) + "deg");
      node.style.setProperty("--gx", Math.round((px + 0.5) * 100) + "%");
      node.style.setProperty("--gy", Math.round((py + 0.5) * 100) + "%");
    });
    node.addEventListener("pointerleave", function () {
      node.style.setProperty("--rx", "0deg"); node.style.setProperty("--ry", "0deg");
    });
    return node;
  }

  // --- shell: sidebar with the case and the sections, content on the right -----------------

  playOnce(document.documentElement, "motion", 1600);
  var app = document.getElementById("app");
  var shellEl = el("div", { cls: "shell" });
  var side = el("aside", { cls: "side" });
  var mainEl = el("main", { cls: "main" });
  shellEl.appendChild(side); shellEl.appendChild(mainEl);
  app.appendChild(shellEl);

  var bad = D.verdict.compromised;
  side.appendChild(el("div", { cls: "brand" }, icon("shield", "brand-ic"),
    el("span", { text: "webforensics" })));
  side.appendChild(el("div", { cls: "side-case" },
    el("div", { cls: "label", text: U["meta.case"] }), el("div", { cls: "side-id", text: D.caseId }),
    el("div", { cls: "status" + (bad ? "" : " clean"), text: bad ? U["stamp.compromised"] : U["stamp.clean"] })));

  var nav = el("nav", { cls: "tabs", role: "tablist", "aria-orientation": "vertical" });
  var panels = {};
  side.appendChild(nav);
  side.appendChild(el("div", { cls: "side-foot", text: "webforensics " + D.tool }));

  mainEl.appendChild(cover());
  mainEl.appendChild(finding());
  var stage = el("div", { cls: "stage" });
  mainEl.appendChild(stage);
  D.tabs.forEach(function (tab) {
    var btn = el("button", {
      role: "tab", id: "tab-" + tab.id, "aria-controls": "panel-" + tab.id,
      onclick: function () { showTab(tab.id, true); }
    }, icon(tab.id), el("span", { text: tab.label }));
    nav.appendChild(btn);
    var panel = el("div", { role: "tabpanel", id: "panel-" + tab.id, "aria-labelledby": "tab-" + tab.id });
    panel.hidden = true;
    panels[tab.id] = panel;
    stage.appendChild(panel);
    if (tab.id === "timeline") buildTimeline(panel);
    else if (tab.id === "flow") buildFlow(panel);
    else if (tab.id === "space") spaceView = buildSpace(panel);
    else tab.sections.forEach(function (s) { panel.appendChild(docSection(s)); });
  });
  mainEl.appendChild(el("footer", { text: U.generated_by }));

  nav.addEventListener("keydown", function (ev) {
    var back = ev.key === "ArrowUp" || ev.key === "ArrowLeft";
    if (!back && ev.key !== "ArrowDown" && ev.key !== "ArrowRight") return;
    ev.preventDefault();
    var ids = D.tabs.map(function (t) { return t.id; });
    var i = ids.indexOf(state.tab) + (back ? -1 : 1);
    showTab(ids[(i + ids.length) % ids.length], true);
    document.getElementById("tab-" + state.tab).focus();
  });

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
    var panel = panels[id];
    playOnce(panel, "enter", 400);
    if (id === "timeline") drawChart();
    if (id === "flow" && !flowShown) {
      flowShown = true;
      playOnce(panel, "play", 700 + panel.querySelectorAll(".flow-node,.flow-link").length * 90);
    }
    if (spaceView) { if (id === "space") spaceView.start(); else spaceView.stop(); }
  }

  window.addEventListener("hashchange", function () { showTab(location.hash.slice(1), false); });

  // --- cover and main finding ------------------------------------------------------------

  function cover() {
    var meta = el("div", { cls: "meta" });
    [[U["meta.generated"], D.generated], [U["meta.zone"], D.zone]].forEach(function (p) {
      meta.appendChild(el("div", null, el("span", { cls: "label", text: p[0] }), el("span", { text: p[1] })));
    });
    return el("header", { cls: "cover" },
      el("div", null, el("div", { cls: "label", text: U.kicker }), el("h1", { text: D.title }), meta),
      el("div", { cls: "stamp" + (bad ? "" : " clean"), role: "img",
        "aria-label": bad ? U["stamp.compromised"] : U["stamp.clean"],
        text: bad ? U["stamp.compromised"] : U["stamp.clean"] }));
  }

  function finding() {
    var v = D.verdict, hero = el("div", { cls: "hero card" + (v.root ? " is-root" : "") });
    if (v.root) {
      var r = v.root;
      hero.appendChild(el("div", { cls: "label" }, icon("root", "lab-ic"), U["verdict.root"]));
      hero.appendChild(el("p", { cls: "entry" },
        el("a", { cls: "n", href: "#timeline", text: no(r.n),
          onclick: function (ev) { ev.preventDefault(); showTab("timeline", true); select(r.n, true); } }),
        el("span", { cls: "when", text: r.day + " " + r.clock + " " + D.zoneShort }), r.text));
      hero.appendChild(el("p", { cls: "entry-sub" }, el("span", { text: r.vuln }),
        meter(r.conf, r.confLabel),
        r.actor ? el("span", { text: U["verdict.from"] + " " + r.actor }) : null));
    } else {
      hero.appendChild(el("div", { cls: "label" }, icon(v.compromised ? "root" : "shield", "lab-ic"),
        v.compromised ? U["verdict.root"] : U["verdict.result"]));
      hero.appendChild(el("p", { cls: "entry-sub", text: v.compromised ? U["verdict.no_root"] : U["verdict.clean"] }));
    }
    var kpis = el("div", { cls: "kpis" });
    [["events", "events", v.stats.events], ["files", "files", v.stats.files],
      ["actors", "actors", v.stats.actors], ["gaps", "gaps", v.stats.gaps]].forEach(function (s, i) {
      kpis.appendChild(tilt(el("div", { cls: "kpi card", style: "--i:" + i },
        el("div", { cls: "kpi-top" }, el("span", { cls: "label", text: U["stat." + s[0]] }), icon(s[1], "kpi-ic")),
        countUp(el("div", { cls: "kpi-val", text: REDUCED ? String(s[2]) : "0" }), s[2]))));
    });
    return el("section", { cls: "finding" }, tilt(hero), kpis);
  }

  // Counts rise to their value once, over about 0.7 s.
  function countUp(node, target) {
    if (REDUCED || !target) { node.textContent = String(target); return node; }
    var start = null, dur = 700, finished = false;
    function step(t) {
      if (finished) return;
      if (start === null) start = t;
      var k = Math.min(1, (t - start) / dur), eased = 1 - Math.pow(1 - k, 3);
      node.textContent = String(Math.round(target * eased));
      if (k < 1) requestAnimationFrame(step); else finished = true;
    }
    requestAnimationFrame(step);
    // The final value is guaranteed even where animation frames are throttled.
    setTimeout(function () { finished = true; node.textContent = String(target); }, dur + 150);
    return node;
  }

  // --- static sections (same content as the HTML report) ---------------------------------

  function docSection(section) {
    var node = el("section", { cls: "sheet doc" }, el("h2", { text: section.title }));
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
      var dl = el("dl", { cls: "fields" });
      b.pairs.forEach(function (p) { field(dl, p[0], p[1]); });
      return dl;
    }
    if (b.t === "table") {
      var head = el("tr");
      b.headers.forEach(function (h) { head.appendChild(el("th", { text: h })); });
      var body = el("tbody");
      b.rows.forEach(function (row, i) {
        var tr = el("tr", { cls: b.hl.indexOf(i) >= 0 ? "hl" : null });
        row.forEach(function (c) {
          if (c.mark && c.mark !== "root") tr.appendChild(el("td", null, meter(c.mark, c.text)));
          else tr.appendChild(el("td", { cls: c.mark === "root" ? "mark-root" : null, text: c.text }));
        });
        body.appendChild(tr);
      });
      return el("div", { cls: "tw" }, el("table", null, el("thead", null, head), body));
    }
    return el("p", { text: "" });
  }

  // --- timeline --------------------------------------------------------------------------

  var svgHost, resetBtn, listEl, countEl, moreBox, detailEl, marks = {}, rows = {};

  function buildTimeline(panel) {
    resetBtn = el("button", {
      cls: "btn", text: U["chart.reset"], hidden: true,
      onclick: function () { state.zoom = null; refresh(); }
    });
    svgHost = el("div");
    var legend = el("div", { cls: "legend" });
    present().forEach(function (c) { legend.appendChild(el("span", null, glyph(c.id), c.label)); });
    var chart = el("div", { cls: "chart" },
      el("div", { cls: "chart-head" }, el("h2", { text: U["chart.title"] }), resetBtn),
      el("p", { cls: "hint", text: U["chart.hint"] }), svgHost, legend);

    var search = el("input", {
      type: "search", placeholder: U["filter.search"], "aria-label": U["filter.search"],
      oninput: function () { state.q = search.value.trim().toLowerCase(); state.limit = PAGE; refresh(); }
    });
    var actor = el("select", {
      "aria-label": U["filter.actor"],
      onchange: function () { state.actor = actor.value; state.limit = PAGE; refresh(); }
    }, el("option", { value: "*", text: U["filter.actor"] }));
    actorList().forEach(function (a) {
      actor.appendChild(el("option", { value: a, text: a || U["chart.files"] }));
    });
    var story = el("input", {
      type: "checkbox", id: "story-only",
      onchange: function () { state.story = story.checked; state.limit = PAGE; refresh(); }
    });
    countEl = el("span", { cls: "count", "aria-live": "polite" });
    var filters = el("div", { cls: "filters" }, search, actor);
    present().forEach(function (c) {
      var chip = el("button", {
        cls: "chip", "aria-pressed": "true",
        onclick: function () {
          state.cats[c.id] = !state.cats[c.id];
          chip.setAttribute("aria-pressed", state.cats[c.id] ? "true" : "false");
          state.limit = PAGE; refresh();
        }
      }, glyph(c.id), c.label);
      filters.appendChild(chip);
    });
    filters.appendChild(el("label", { cls: "toggle", for: "story-only" }, story, U["filter.story"]));
    filters.appendChild(countEl);

    var head = el("div", { cls: "reg-head", "aria-hidden": "true" },
      el("span", { cls: "label", text: U["col.n"] }),
      el("span", { cls: "label", text: U["col.time"] + " " + D.zoneShort }),
      el("span", { cls: "label", text: U["col.actor"] }),
      el("span", { cls: "label", text: U["col.event"] }),
      el("span", { cls: "label", text: U["col.confidence"] }));
    listEl = el("ol", { cls: "events" });
    moreBox = el("div", { cls: "more" });
    detailEl = el("aside", { cls: "detail", "aria-live": "polite" });
    var main = el("div", null, chart, filters, head, listEl, moreBox);
    panel.appendChild(el("div", { cls: "tl" }, main, detailEl));
    renderDetail();
    renderList();

    if (window.ResizeObserver) {
      var pending = null;
      new ResizeObserver(function () {
        if (pending) cancelAnimationFrame(pending);
        pending = requestAnimationFrame(function () { if (state.tab === "timeline") drawChart(); });
      }).observe(svgHost);
    }
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape") detailEl.classList.remove("open");
    });
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
    var r = root ? 6.5 : 5, color = "var(--c-" + cat + ")", node;
    if (cat === "recon") node = sv("circle", { cx: x, cy: y, r: r - 1, fill: "var(--surface)", stroke: color, "stroke-width": 2 });
    else if (cat === "exploit") node = sv("polygon", { points: [x, y - r - 1, x + r + 1, y + r, x - r - 1, y + r].join(" "), fill: color });
    else if (cat === "login") node = sv("polygon", { points: [x, y - r - 1, x + r + 1, y, x, y + r + 1, x - r - 1, y].join(" "), fill: color });
    else if (cat === "write") node = sv("rect", { x: x - r + 0.5, y: y - r + 0.5, width: 2 * r - 1, height: 2 * r - 1, fill: color });
    else if (cat === "file") node = sv("rect", { x: x - r + 1, y: y - r + 1, width: 2 * r - 2, height: 2 * r - 2, fill: "var(--surface)", stroke: color, "stroke-width": 2 });
    else if (cat === "use") node = sv("circle", { cx: x, cy: y, r: r - 0.5, fill: color });
    else node = sv("circle", { cx: x, cy: y, r: 2.5, fill: color });
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
    var left = width < 520 ? 96 : 138, right = 16, top = 20, laneH = 28, axisH = 24;
    var lanes = D.lanes.slice();
    var othersLane = hasOthers ? lanes.length : -1;
    var laneCount = lanes.length + (hasOthers ? 1 : 0);
    var plotH = laneCount * laneH;
    var height = top + plotH + axisH;
    var shown = events.filter(matches);
    var lo = state.zoom ? state.zoom[0] : events[0].ms;
    var hi = state.zoom ? state.zoom[1] : events[events.length - 1].ms;
    if (hi - lo < 10000) { var mid = (hi + lo) / 2; lo = mid - 5000; hi = mid + 5000; }
    var pad = state.zoom ? 0 : (hi - lo) * 0.04;
    lo -= pad; hi += pad;
    var plotW = width - left - right;
    function x(ms) { return left + (ms - lo) / (hi - lo) * plotW; }

    var svg = sv("svg", { viewBox: "0 0 " + width + " " + height, height: height, role: "img",
      "aria-label": U["chart.title"] });
    var defs = sv("defs", {});
    var hatch = sv("pattern", { id: "hatch", patternUnits: "userSpaceOnUse", width: 6, height: 6,
      patternTransform: "rotate(45)" });
    hatch.appendChild(sv("line", { "class": "hatchline", x1: 0, y1: 0, x2: 0, y2: 6 }));
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
        var gl = sv("text", { "class": "gaplabel", x: x0 + 3, y: top - 6 });
        gl.textContent = g.label;
        svg.appendChild(gl);
      }
    });
    ticks(lo, hi).forEach(function (t) {
      var tx = x(t.ms);
      svg.appendChild(sv("line", { "class": "tick", x1: tx, x2: tx, y1: top, y2: top + plotH + 4 }));
      var tl = sv("text", { "class": "axis", x: tx, y: top + plotH + 16, "text-anchor": "middle" });
      tl.textContent = t.label;
      svg.appendChild(tl);
    });
    for (var i = 0; i < laneCount; i++) {
      var y = top + i * laneH + laneH / 2;
      svg.appendChild(sv("line", { "class": "base", x1: left, x2: width - right, y1: y, y2: y }));
      var name = i === othersLane ? U["chart.others"] : (lanes[i] || U["chart.files"]);
      var label = sv("text", { "class": "lane" + (attacker[lanes[i]] ? " att" : ""), x: left - 10,
        y: y + 4, "text-anchor": "end" });
      label.textContent = name.length > 17 ? name.slice(0, 16) + "…" : name;
      label.appendChild(titleNode(name));
      svg.appendChild(label);
    }

    // The first drawing plays once: marks appear in time order, then the root line is drawn.
    var play = !chartPlayed && !REDUCED && shown.length <= POP_LIMIT;
    chartPlayed = true;
    var root = events.filter(function (e) { return e.root; })[0];
    if (root && root.ms >= lo && root.ms <= hi && matches(root)) {
      var rx = x(root.ms);
      svg.appendChild(sv("line", { "class": "rootline", x1: rx, x2: rx,
        y1: top - 4, y2: top + plotH }));
      var tagText = U["chart.root"].toUpperCase() + " " + no(root.n);
      var tagW = tagText.length * 6.2 + 8, tagX = Math.min(rx, width - right - tagW);
      svg.appendChild(sv("rect", { "class": "roottagbg", x: tagX, y: top - 19, width: tagW, height: 14 }));
      var tag = sv("text", { "class": "roottag", x: tagX + 4, y: top - 8 });
      tag.textContent = tagText;
      svg.appendChild(tag);
    }

    var brush = sv("rect", { "class": "brush", x: 0, y: top, width: 0, height: plotH, visibility: "hidden" });
    svg.appendChild(brush);
    marks = {};
    shown.forEach(function (e) {
      var lane = e.actor in laneOf ? laneOf[e.actor] : othersLane;
      var mx = x(e.ms);
      var node = mark(e.cat, mx, top + lane * laneH + laneH / 2, e.root);
      node.setAttribute("class", "ev" + (state.sel === e.n ? " sel" : ""));
      if (play) node.style.animationDelay = Math.round((mx - left) / plotW * 700) + "ms";
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
    if (play) playOnce(svg, "pop", 1600);
  }

  function titleNode(text) {
    var t = document.createElementNS(SVGNS, "title");
    t.textContent = text;
    return t;
  }

  var STEPS = [1, 5, 15, 30, 60, 300, 900, 1800, 3600, 10800, 21600, 43200, 86400, 604800]
    .map(function (s) { return s * 1000; });

  function ticks(lo, hi) {
    var span = hi - lo, step = STEPS[STEPS.length - 1];
    for (var i = 0; i < STEPS.length; i++) { if (span / STEPS[i] <= 6) { step = STEPS[i]; break; } }
    var off = D.offsetMin * 60000, out = [];
    var first = Math.ceil((lo + off) / step) * step - off;
    var multiDay = span > 86400000;
    for (var ms = first; ms <= hi; ms += step) {
      var d = new Date(ms + off);
      var hm = pad2(d.getUTCHours()) + ":" + pad2(d.getUTCMinutes());
      if (step < 60000) hm += ":" + pad2(d.getUTCSeconds());
      var label = multiDay ? pad2(d.getUTCDate()) + "/" + pad2(d.getUTCMonth() + 1) + (step < 86400000 ? " " + hm : "") : hm;
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
    if (!all.length) listEl.appendChild(el("li", { cls: "empty", text: U["filter.none"] }));
    var openedRun = {}, day = null;
    all.slice(0, state.limit).forEach(function (r) {
      if (r.e.day !== day) {
        day = r.e.day;
        listEl.appendChild(el("li", { cls: "day", text: day }));
      }
      if (r.run !== undefined) { listEl.appendChild(runRow(r.run, false)); return; }
      if (r.sub && !openedRun[r.e.run]) { openedRun[r.e.run] = true; listEl.appendChild(runRow(r.e.run, true)); }
      listEl.appendChild(eventRow(r.e, r.sub));
    });
    moreBox.textContent = "";
    if (all.length > state.limit) {
      moreBox.appendChild(el("button", {
        cls: "btn", text: fmt(U["filter.more"], { count: Math.min(PAGE, all.length - state.limit) }),
        onclick: function () { state.limit += PAGE; renderList(); }
      }));
    }
  }

  function runRow(id, opened) {
    var run = D.runs[id], first = byN[run.first];
    var toggle = function () { state.open[id] = !state.open[id]; renderList(); };
    return el("li", {
      cls: "runrow", tabindex: "0", role: "button", "aria-expanded": opened ? "true" : "false",
      onclick: toggle,
      onkeydown: function (ev) { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggle(); } }
    },
      el("span", { cls: "n", text: no(run.first) }),
      el("span", { cls: "time", text: run.clock }),
      el("span", { cls: "actor", text: first.actor || D.labels.noActor }),
      el("span", { cls: "text" }, glyph(first.cat), el("span", { text: run.text })),
      el("span", null, el("span", { cls: "btn", text: opened ? U["run.collapse"] : fmt(U["run.expand"], { count: run.count }) })));
  }

  function eventRow(e, sub) {
    var cls = [sub ? "sub" : "", e.root ? "root" : "", state.sel === e.n ? "sel" : ""].join(" ").trim();
    var text = el("span", null, e.root ? el("span", { cls: "tag", text: D.labels.rootMarker }) : null, e.text);
    var li = el("li", {
      cls: cls || null, tabindex: "0", "data-n": String(e.n),
      onclick: function () { select(e.n, false); },
      onkeydown: function (ev) { onRowKey(ev, e.n); }
    },
      el("span", { cls: "n", text: no(e.n) }),
      el("span", { cls: "time", text: e.clock }),
      el("span", { cls: "actor", text: e.actor || D.labels.noActor }),
      el("span", { cls: "text" }, glyph(e.cat), text),
      el("span", null, meter(e.conf, e.confLabel)));
    rows[e.n] = li;
    return li;
  }

  function onRowKey(ev, n) {
    if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); select(n, false); return; }
    if (ev.key !== "ArrowDown" && ev.key !== "ArrowUp") return;
    ev.preventDefault();
    var items = Array.prototype.slice.call(listEl.querySelectorAll("li[tabindex]"));
    var i = items.indexOf(ev.currentTarget) + (ev.key === "ArrowDown" ? 1 : -1);
    if (items[i]) items[i].focus();
  }

  // Selecting from the chart or the finding may need to open a burst, clear filters that
  // hide the event, or show more rows before the row exists.
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
    for (var k in marks) marks[k].setAttribute("class", "ev" + (Number(k) === n ? " sel" : ""));
    renderDetail();
    detailEl.classList.add("open");
    if (rows[n] && reveal) rows[n].scrollIntoView({ block: "nearest" });
  }

  function syncFilterControls() {
    var panel = panels.timeline;
    panel.querySelector("input[type=search]").value = "";
    panel.querySelector("select").value = "*";
    panel.querySelector("#story-only").checked = false;
    Array.prototype.forEach.call(panel.querySelectorAll(".chip"), function (c) {
      c.setAttribute("aria-pressed", "true");
    });
    resetBtn.hidden = true;
  }

  function renderDetail() {
    detailEl.textContent = "";
    var e = state.sel !== null ? byN[state.sel] : null;
    var close = el("button", { cls: "btn close", text: U["detail.close"],
      onclick: function () { detailEl.classList.remove("open"); } });
    detailEl.appendChild(el("div", { cls: "head" },
      el("div", null, el("div", { cls: "label", text: U["detail.title"] }),
        el("div", { cls: "no", text: e ? no(e.n) : "—" })), close));
    if (!e) { detailEl.appendChild(el("p", { cls: "empty", text: U["detail.empty"] })); return; }
    var body = el("div", { cls: "body" });
    if (e.root) body.appendChild(el("div", { cls: "rootnote", text: U["detail.root"] }));
    body.appendChild(el("p", { cls: "text" }, glyph(e.cat), " ", e.text));
    var dl = el("dl", { cls: "fields" });
    field(dl, U["detail.time"], e.day + " " + e.clock + " " + D.zoneShort);
    field(dl, U["detail.basis"], e.basis);
    field(dl, U["detail.phase"], e.phase);
    field(dl, U["detail.actor"], e.actor || D.labels.noActor);
    field(dl, U["detail.confidence"], meter(e.conf, e.confLabel));
    body.appendChild(dl);
    if (e.notes.length) {
      body.appendChild(el("h3", { text: U["detail.notes"] }));
      var ul = el("ul");
      e.notes.forEach(function (t) { ul.appendChild(el("li", { text: t })); });
      body.appendChild(ul);
    }
    body.appendChild(el("h3", { text: U["detail.evidence"] }));
    e.cites.forEach(function (i) {
      var c = D.cites[i];
      var btn = el("button", { cls: "btn", text: U.copy });
      btn.addEventListener("click", function () { copy(c.ref + "\n" + c.ex, btn); });
      body.appendChild(el("div", { cls: "cite" },
        el("div", { cls: "ref" }, el("span", { text: c.ref }), btn),
        c.ex ? el("pre", { text: c.ex }) : null));
    });
    detailEl.appendChild(body);
    playOnce(body, "enter", 400);
  }

  function openEvent(n) {
    showTab("timeline", true);
    select(n, true);
  }

  // --- attack flow: the incident's main steps as a chain ---------------------------------

  function buildFlow(panel) {
    var steps = events.filter(function (e) { return e.story || e.root; });
    panel.appendChild(el("div", { cls: "chart-head" }, el("h2", { text: U["flow.title"] })));
    panel.appendChild(el("p", { cls: "hint", text: steps.length ? U["flow.hint"] : U["flow.none"] }));
    if (!steps.length) return;
    var list = el("ol", { cls: "flow" });
    var actors = D.attackers.length ? D.attackers.join(", ") : D.labels.noActor;
    list.appendChild(el("li", { cls: "flow-node actor", style: "--i:0" },
      el("div", { cls: "label", text: U["flow.actor"] }), el("div", { cls: "flow-actor", text: actors })));
    steps.forEach(function (e, i) {
      list.appendChild(el("li", { cls: "flow-link", style: "--i:" + (2 * i + 1) },
        el("span", { text: U["flow.rel." + e.cat] || U["flow.rel.other"] })));
      var open = function () { openEvent(e.n); };
      list.appendChild(el("li", {
        cls: "flow-node" + (e.root ? " root" : ""), style: "--i:" + (2 * i + 2), tabindex: "0",
        role: "button", onclick: open,
        onkeydown: function (ev) { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); open(); } }
      },
        el("div", { cls: "flow-meta" }, glyph(e.cat), el("span", { cls: "n", text: no(e.n) }),
          el("span", { text: e.day + " " + e.clock + " " + D.zoneShort }),
          e.root ? el("span", { cls: "tag", text: D.labels.rootMarker }) : null),
        el("div", { cls: "flow-text", text: e.text }),
        el("div", { cls: "flow-foot" }, el("span", { text: e.actor || D.labels.noActor }),
          meter(e.conf, e.confLabel))));
    });
    panel.appendChild(list);
  }

  // --- 3D space: time x actor x kind, drawn on a canvas without any library -----------------

  function buildSpace(panel) {
    var canvas = el("canvas", { cls: "space", role: "img", "aria-label": U["space.title"] });
    var tip = el("div", { cls: "space-tip", hidden: true });
    var reset = el("button", { cls: "btn", text: U["space.reset"], onclick: function () { home(); draw(); } });
    var legend = el("div", { cls: "legend" });
    present().forEach(function (c) { legend.appendChild(el("span", null, glyph(c.id), c.label)); });
    panel.appendChild(el("div", { cls: "chart-head" }, el("h2", { text: U["space.title"] }), reset));
    panel.appendChild(el("p", { cls: "hint", text: events.length ? U["space.hint"] : U["chart.empty"] }));
    if (!events.length) return { start: function () {}, stop: function () {} };
    panel.appendChild(el("div", { cls: "space-box" }, canvas, tip));
    panel.appendChild(legend);

    var kinds = present().map(function (c) { return c.id; });
    var lanes = D.lanes.concat(hasOthers ? [null] : []);
    var t0 = events[0].ms, t1 = events[events.length - 1].ms;
    var span = Math.max(1, t1 - t0);
    var FLOOR = -0.55;
    function laneZ(i) { return lanes.length > 1 ? -0.7 + 1.4 * i / (lanes.length - 1) : 0; }
    var pts = events.map(function (e) {
      var lane = e.actor in laneOf ? laneOf[e.actor] : lanes.length - 1;
      return {
        e: e,
        x: -1 + 2 * (e.ms - t0) / span,
        y: FLOOR + 1.1 * (kinds.indexOf(e.cat) + 1) / (kinds.length + 1),
        z: laneZ(lane)
      };
    });
    var cam, drag = null, moved = false, running = false, auto = !REDUCED, raf = 0, hover = null;
    var proj = [];

    function home() { cam = { yaw: -0.65, pitch: 0.42, dist: 3.6 }; }
    home();

    function project(x, y, z, W, H) {
      var cy = Math.cos(cam.yaw), sy = Math.sin(cam.yaw), cp = Math.cos(cam.pitch), sp = Math.sin(cam.pitch);
      var x1 = x * cy - z * sy, z1 = x * sy + z * cy;
      var y1 = y * cp - z1 * sp, z2 = y * sp + z1 * cp;
      var f = Math.min(W, H * 1.7) * 1.05 / (cam.dist - z2);
      return { x: W / 2 + x1 * f, y: H * 0.5 - y1 * f, d: z2, s: f };
    }

    function size() {
      var ratio = window.devicePixelRatio || 1, w = canvas.clientWidth || 800;
      var h = Math.max(300, Math.min(560, Math.round(w * 0.56)));
      if (canvas.width !== Math.round(w * ratio) || canvas.height !== Math.round(h * ratio)) {
        canvas.width = Math.round(w * ratio); canvas.height = Math.round(h * ratio);
        canvas.style.height = h + "px";
      }
      return { w: w, h: h, r: ratio };
    }

    function line(g, a, b) { g.beginPath(); g.moveTo(a.x, a.y); g.lineTo(b.x, b.y); g.stroke(); }

    function shape(g, cat, p, r, color, bg) {
      g.fillStyle = color; g.strokeStyle = color; g.lineWidth = 1.6;
      g.beginPath();
      if (cat === "exploit") { g.moveTo(p.x, p.y - r * 1.15); g.lineTo(p.x + r, p.y + r * 0.8); g.lineTo(p.x - r, p.y + r * 0.8); g.closePath(); g.fill(); }
      else if (cat === "login") { g.moveTo(p.x, p.y - r); g.lineTo(p.x + r, p.y); g.lineTo(p.x, p.y + r); g.lineTo(p.x - r, p.y); g.closePath(); g.fill(); }
      else if (cat === "write") { g.rect(p.x - r * 0.85, p.y - r * 0.85, r * 1.7, r * 1.7); g.fill(); }
      else if (cat === "file") { g.fillStyle = bg; g.rect(p.x - r * 0.8, p.y - r * 0.8, r * 1.6, r * 1.6); g.fill(); g.stroke(); }
      else if (cat === "recon") { g.fillStyle = bg; g.arc(p.x, p.y, r * 0.85, 0, 6.2832); g.fill(); g.stroke(); }
      else if (cat === "use") { g.arc(p.x, p.y, r * 0.9, 0, 6.2832); g.fill(); }
      else { g.arc(p.x, p.y, r * 0.45, 0, 6.2832); g.fill(); }
    }

    function draw() {
      var S = size(), g = canvas.getContext("2d"), W = S.w, H = S.h;
      g.setTransform(S.r, 0, 0, S.r, 0, 0);
      g.clearRect(0, 0, W, H);
      var rule = css("--rule"), rule2 = css("--rule-2"), muted = css("--muted"), ink = css("--ink"),
        bg = css("--surface"), red = css("--red"), mono = "11px " + css("--mono");
      var colors = {};
      kinds.concat(["other"]).forEach(function (k) { colors[k] = css("--c-" + k); });
      // Floor grid: one line per lane and one per time tick.
      g.strokeStyle = rule; g.lineWidth = 1;
      lanes.forEach(function (a, i) {
        line(g, project(-1, FLOOR, laneZ(i), W, H), project(1, FLOOR, laneZ(i), W, H));
      });
      var tk = ticks(t0, t0 + span);
      tk.forEach(function (t) {
        var x = -1 + 2 * (t.ms - t0) / span;
        line(g, project(x, FLOOR, -0.8, W, H), project(x, FLOOR, 0.8, W, H));
      });
      // Axes from the near-left corner.
      g.strokeStyle = rule2; g.lineWidth = 1.2;
      var o = project(-1.05, FLOOR, -0.8, W, H);
      line(g, o, project(1.1, FLOOR, -0.8, W, H));
      line(g, o, project(-1.05, 0.65, -0.8, W, H));
      line(g, o, project(-1.05, FLOOR, 0.85, W, H));
      g.font = mono; g.fillStyle = muted;
      var at = project(1.12, FLOOR - 0.08, -0.95, W, H); g.fillText(U["space.time"], at.x, at.y);
      var ak = project(-1.05, 0.72, -0.8, W, H); g.fillText(U["space.kind"], ak.x - 10, ak.y);
      var aa = project(-1.05, FLOOR, 0.95, W, H); g.fillText(U["space.actor"], aa.x - 10, aa.y);
      tk.forEach(function (t) {
        var p = project(-1 + 2 * (t.ms - t0) / span, FLOOR, -0.92, W, H);
        g.fillText(t.label, p.x - 14, p.y + 12);
      });
      lanes.forEach(function (a, i) {
        var p = project(1.05, FLOOR, laneZ(i), W, H);
        var name = a === null ? U["chart.others"] : (a || U["chart.files"]);
        g.fillStyle = attacker[a] ? ink : muted;
        g.fillText(name.length > 16 ? name.slice(0, 15) + "…" : name, p.x + 4, p.y + 4);
      });
      // Points, far to near, each with a faint drop line to the floor.
      proj = pts.map(function (q) {
        return { q: q, p: project(q.x, q.y, q.z, W, H), f: project(q.x, FLOOR, q.z, W, H) };
      });
      proj.sort(function (a, b) { return a.p.d - b.p.d; });
      var drops = proj.length <= 600;
      proj.forEach(function (it) {
        var e = it.q.e, r = Math.max(2.5, Math.min(8, it.p.s * 0.022)) * (e.root ? 1.35 : 1);
        if (drops) { g.strokeStyle = rule; g.lineWidth = 1; line(g, it.p, it.f); }
        shape(g, e.cat, it.p, r, colors[e.cat] || colors.other, bg);
        if (e.root) {
          g.strokeStyle = red; g.lineWidth = 1.5; g.beginPath(); g.arc(it.p.x, it.p.y, r + 5, 0, 6.2832); g.stroke();
          g.fillStyle = red; g.font = mono;
          g.fillText(U["chart.root"].toUpperCase() + " " + no(e.n), it.p.x + r + 8, it.p.y - r - 4);
        }
        if (state.sel === e.n || hover === e.n) {
          g.strokeStyle = ink; g.lineWidth = 2; g.beginPath(); g.arc(it.p.x, it.p.y, r + 3, 0, 6.2832); g.stroke();
        }
      });
    }

    function loop() {
      if (!running) return;
      if (auto && !drag) cam.yaw += 0.0025;
      draw();
      raf = requestAnimationFrame(loop);
    }

    function pick(ev) {
      var b = canvas.getBoundingClientRect(), mx = ev.clientX - b.left, my = ev.clientY - b.top;
      var best = null, bd = 144;
      proj.forEach(function (it) {
        var dx = it.p.x - mx, dy = it.p.y - my, d = dx * dx + dy * dy;
        if (d < bd) { bd = d; best = it; }
      });
      return best;
    }

    canvas.addEventListener("pointerdown", function (ev) {
      drag = { x: ev.clientX, y: ev.clientY }; moved = false; auto = false;
      canvas.setPointerCapture(ev.pointerId);
    });
    canvas.addEventListener("pointermove", function (ev) {
      if (drag) {
        var dx = ev.clientX - drag.x, dy = ev.clientY - drag.y;
        if (Math.abs(dx) + Math.abs(dy) > 3) moved = true;
        cam.yaw += dx * 0.008;
        cam.pitch = Math.max(-0.1, Math.min(1.35, cam.pitch + dy * 0.006));
        drag = { x: ev.clientX, y: ev.clientY };
        if (!running) draw();
        return;
      }
      var it = pick(ev);
      hover = it ? it.q.e.n : null;
      canvas.style.cursor = it ? "pointer" : "grab";
      if (it) {
        var b = canvas.getBoundingClientRect();
        tip.hidden = false;
        tip.textContent = no(it.q.e.n) + "  " + it.q.e.clock + "  " + (it.q.e.actor || U["chart.files"]) +
          "\n" + it.q.e.text;
        tip.style.left = Math.max(0, Math.min(it.p.x + 14, b.width - 300)) + "px";
        tip.style.top = (it.p.y + 12) + "px";
      } else { tip.hidden = true; }
      if (!running) draw();
    });
    canvas.addEventListener("pointerup", function (ev) {
      var wasDrag = moved;
      drag = null;
      if (!wasDrag) { var it = pick(ev); if (it) openEvent(it.q.e.n); }
    });
    canvas.addEventListener("pointerleave", function () { hover = null; tip.hidden = true; if (!running) draw(); });
    canvas.addEventListener("wheel", function (ev) {
      ev.preventDefault(); auto = false;
      cam.dist = Math.max(2.2, Math.min(7, cam.dist * (ev.deltaY > 0 ? 1.08 : 0.93)));
      if (!running) draw();
    }, { passive: false });

    return {
      start: function () {
        if (running) return;
        if (REDUCED) { draw(); return; }
        running = true; loop();
      },
      stop: function () { running = false; cancelAnimationFrame(raf); }
    };
  }

  function copy(text, btn) {
    function done() { btn.textContent = U.copied; setTimeout(function () { btn.textContent = U.copy; }, 1200); }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { fallback(text); done(); });
    } else { fallback(text); done(); }
  }

  function fallback(text) {
    var area = el("textarea", { readonly: true, style: "position:fixed;opacity:0" });
    area.value = text;
    document.body.appendChild(area);
    area.select();
    try { document.execCommand("copy"); } catch (err) { /* nothing else to try offline */ }
    document.body.removeChild(area);
  }

  showTab(location.hash.slice(1) || "overview", false);
})();
