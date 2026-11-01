"use strict";
(function () {
  // Every string comes from the embedded JSON (often attacker-controlled log text).
  // It is only ever set with textContent or as an attribute value; never as markup.
  var D = JSON.parse(document.getElementById("data").textContent);
  var U = D.ui;
  var SVGNS = "http://www.w3.org/2000/svg";
  var PAGE = 200;

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

  function catVar(cat) { return "var(--c-" + cat + ")"; }

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
  var hasOthers = events.some(function (e) { return !(e.actor in laneOf); });

  var state = {
    tab: "overview", sel: null, q: "", actor: "*", story: false, limit: PAGE,
    cats: {}, open: {}, zoom: null
  };
  D.categories.forEach(function (c) { state.cats[c.id] = true; });

  // --- shell -----------------------------------------------------------------------------

  var app = document.getElementById("app");
  var wrap = el("div", { cls: "wrap" });
  app.appendChild(wrap);

  wrap.appendChild(el("header", null,
    el("h1", { text: D.title }), el("p", { cls: "sub", text: D.subtitle })));
  wrap.appendChild(verdictCard());

  var nav = el("nav", { cls: "tabs", role: "tablist" });
  var panels = {};
  wrap.appendChild(nav);
  D.tabs.forEach(function (tab) {
    var btn = el("button", {
      role: "tab", id: "tab-" + tab.id, "aria-controls": "panel-" + tab.id,
      text: tab.label, onclick: function () { showTab(tab.id, true); }
    });
    nav.appendChild(btn);
    var panel = el("div", { role: "tabpanel", id: "panel-" + tab.id, "aria-labelledby": "tab-" + tab.id });
    panel.hidden = true;
    panels[tab.id] = panel;
    wrap.appendChild(panel);
    if (tab.id === "timeline") buildTimeline(panel);
    else tab.sections.forEach(function (s) { panel.appendChild(docSection(s)); });
  });
  wrap.appendChild(el("footer", { text: U.generated_by }));

  nav.addEventListener("keydown", function (ev) {
    if (ev.key !== "ArrowRight" && ev.key !== "ArrowLeft") return;
    var ids = D.tabs.map(function (t) { return t.id; });
    var i = ids.indexOf(state.tab) + (ev.key === "ArrowRight" ? 1 : -1);
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
    if (id === "timeline") drawChart();
  }

  window.addEventListener("hashchange", function () { showTab(location.hash.slice(1), false); });

  // --- verdict ---------------------------------------------------------------------------

  function verdictCard() {
    var v = D.verdict;
    var left = el("div", null, el("div", {
      cls: "state", text: v.compromised ? U["verdict.compromised"] : U["verdict.clean"]
    }));
    if (v.root) {
      var link = el("a", {
        href: "#timeline", text: "#" + v.root.n,
        onclick: function (ev) { ev.preventDefault(); showTab("timeline", true); select(v.root.n, true); }
      });
      left.appendChild(el("div", { cls: "root" },
        el("b", { text: U["verdict.root"] + ": " }), link, " " + v.root.time + " · " + v.root.text));
      left.appendChild(el("div", { cls: "root" },
        el("b", { text: v.root.vuln + " · " }),
        el("span", { cls: "badge conf-" + v.root.conf, text: v.root.confLabel })));
    } else if (v.compromised) {
      left.appendChild(el("div", { cls: "root", text: U["verdict.no_root"] }));
    }
    var stats = el("div", { cls: "stats" });
    [["events", v.stats.events], ["files", v.stats.files], ["actors", v.stats.actors],
      ["gaps", v.stats.gaps]].forEach(function (s) {
      stats.appendChild(el("div", { cls: "stat" },
        el("strong", { text: String(s[1]) }), el("span", { text: U["stat." + s[0]] })));
    });
    return el("div", { cls: "card verdict" + (v.compromised ? "" : " clean") }, left, stats);
  }

  // --- static sections (same content as the HTML report) ---------------------------------

  function docSection(section) {
    var node = el("section", { cls: "card doc" }, el("h2", { text: section.title }));
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
      var dl = el("dl");
      b.pairs.forEach(function (p) { dl.appendChild(el("dt", { text: p[0] })); dl.appendChild(el("dd", { text: p[1] })); });
      return dl;
    }
    if (b.t === "table") {
      var head = el("tr");
      b.headers.forEach(function (h) { head.appendChild(el("th", { text: h })); });
      var body = el("tbody");
      b.rows.forEach(function (row, i) {
        var tr = el("tr", { cls: b.hl.indexOf(i) >= 0 ? "hl" : null });
        row.forEach(function (c) {
          var cls = c.mark === "root" ? "mark-root" : c.mark ? "conf-" + c.mark : null;
          tr.appendChild(el("td", { cls: cls, text: c.text }));
        });
        body.appendChild(tr);
      });
      return el("div", { cls: "tw" }, el("table", null, el("thead", null, head), body));
    }
    return el("p", { text: "" });
  }

  // --- timeline --------------------------------------------------------------------------

  var chartBox, svgHost, resetBtn, listEl, countEl, moreBox, detailEl, dots = {}, rows = {};

  function buildTimeline(panel) {
    resetBtn = el("button", {
      cls: "btn", text: "Reset zoom", hidden: true,
      onclick: function () { state.zoom = null; refresh(); }
    });
    svgHost = el("div");
    var legend = el("div", { cls: "legend" });
    present().forEach(function (c) {
      legend.appendChild(el("span", null, el("i", { style: "background:" + catVar(c.id) }), c.label));
    });
    chartBox = el("div", { cls: "card chart" },
      el("div", { cls: "bar" }, el("h2", { text: U["chart.title"] }), resetBtn),
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
    var chips = present().map(function (c) {
      var chip = el("button", {
        cls: "chip", "aria-pressed": "true",
        onclick: function () {
          state.cats[c.id] = !state.cats[c.id];
          chip.setAttribute("aria-pressed", state.cats[c.id] ? "true" : "false");
          state.limit = PAGE; refresh();
        }
      }, el("i", { style: "background:" + catVar(c.id) }), c.label);
      return chip;
    });
    var story = el("input", {
      type: "checkbox", id: "story-only",
      onchange: function () { state.story = story.checked; state.limit = PAGE; refresh(); }
    });
    countEl = el("span", { cls: "count", "aria-live": "polite" });
    var filters = el("div", { cls: "filters" }, search, actor);
    chips.forEach(function (c) { filters.appendChild(c); });
    filters.appendChild(el("label", { cls: "toggle", for: "story-only" }, story, U["filter.story"]));
    filters.appendChild(countEl);

    listEl = el("ol", { cls: "events" });
    moreBox = el("div", { cls: "more" });
    detailEl = el("aside", { cls: "card detail", "aria-live": "polite" });
    var main = el("div", null, chartBox, el("div", { cls: "card" }, filters, listEl, moreBox));
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

  // Chart: one lane per actor, x = time in the report's zone, grey bands = evidence gaps.
  function drawChart() {
    if (!svgHost || state.tab !== "timeline") return;
    if (!events.length) {
      svgHost.textContent = "";
      svgHost.appendChild(el("p", { cls: "empty", text: U["chart.empty"] }));
      return;
    }
    var width = Math.max(320, svgHost.clientWidth || 800);
    var left = width < 520 ? 92 : 140, right = 14, top = 6, laneH = 26, axisH = 24;
    var lanes = D.lanes.slice();
    var othersLane = hasOthers ? lanes.length : -1;
    var laneCount = lanes.length + (hasOthers ? 1 : 0);
    var height = top + laneCount * laneH + axisH;
    var shown = events.filter(matches);
    var all = events;
    var lo = state.zoom ? state.zoom[0] : all[0].ms;
    var hi = state.zoom ? state.zoom[1] : all[all.length - 1].ms;
    if (hi - lo < 10000) { var mid = (hi + lo) / 2; lo = mid - 5000; hi = mid + 5000; }
    var pad = state.zoom ? 0 : (hi - lo) * 0.04;
    lo -= pad; hi += pad;
    var plotW = width - left - right;
    function x(ms) { return left + (ms - lo) / (hi - lo) * plotW; }

    var svg = sv("svg", { viewBox: "0 0 " + width + " " + height, height: height, role: "img",
      "aria-label": U["chart.title"] });
    var plotH = laneCount * laneH;
    D.gaps.forEach(function (g) {
      if (g.to < lo || g.from > hi) return;
      var x0 = x(Math.max(g.from, lo)), x1 = x(Math.min(g.to, hi));
      var band = sv("rect", { "class": "gapband", x: x0, y: top, width: Math.max(1, x1 - x0), height: plotH });
      band.appendChild(titleNode(g.label + " · " + g.kind));
      svg.appendChild(band);
      if (x1 - x0 > 18) {
        var gl = sv("text", { "class": "gaplabel", x: x0 + 3, y: top + 9 });
        gl.textContent = g.label;
        svg.appendChild(gl);
      }
    });
    for (var i = 0; i < laneCount; i++) {
      var y = top + i * laneH + laneH / 2;
      svg.appendChild(sv("line", { "class": "grid", x1: left, x2: width - right, y1: y, y2: y }));
      var name = i === othersLane ? U["chart.others"] : (lanes[i] || U["chart.files"]);
      var label = sv("text", { "class": "lane-label", x: left - 8, y: y + 4, "text-anchor": "end" });
      label.textContent = name.length > 18 ? name.slice(0, 17) + "…" : name;
      label.appendChild(titleNode(name));
      svg.appendChild(label);
    }
    ticks(lo, hi).forEach(function (t) {
      var tx = x(t.ms);
      svg.appendChild(sv("line", { "class": "grid", x1: tx, x2: tx, y1: top, y2: top + plotH, "stroke-dasharray": "2 3" }));
      var tl = sv("text", { "class": "axis", x: tx, y: top + plotH + 15, "text-anchor": "middle" });
      tl.textContent = t.label;
      svg.appendChild(tl);
    });

    var brush = sv("rect", { "class": "brush", x: 0, y: top, width: 0, height: plotH, visibility: "hidden" });
    svg.appendChild(brush);
    dots = {};
    shown.forEach(function (e) {
      var lane = e.actor in laneOf ? laneOf[e.actor] : othersLane;
      var cy = top + lane * laneH + laneH / 2, cx = x(e.ms);
      if (e.root) svg.appendChild(sv("circle", { "class": "rootring", cx: cx, cy: cy, r: 9 }));
      var dot = sv("circle", {
        "class": "dot" + (state.sel === e.n ? " sel" : ""), cx: cx, cy: cy, r: e.root ? 6 : 4.5,
        fill: catVar(e.cat), tabindex: "-1"
      });
      dot.appendChild(titleNode("#" + e.n + " " + e.time + " · " + (e.actor || U["chart.files"]) + "\n" + e.text));
      dot.addEventListener("click", function (ev) { ev.stopPropagation(); select(e.n, true); });
      dots[e.n] = dot;
      svg.appendChild(dot);
    });

    // Drag across the chart to zoom into that time range.
    var start = null;
    function px(ev) {
      var r = svg.getBoundingClientRect();
      return (ev.clientX - r.left) * (width / r.width);
    }
    svg.addEventListener("pointerdown", function (ev) {
      if (ev.target.classList && ev.target.classList.contains("dot")) return;
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

  // List: bursts from one actor collapse into one row until opened.
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
    var openedRun = {};
    all.slice(0, state.limit).forEach(function (r) {
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
    var li = el("li", {
      cls: "runrow", tabindex: "0", role: "button", "aria-expanded": opened ? "true" : "false",
      onclick: toggle,
      onkeydown: function (ev) { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggle(); } }
    },
      el("span", { cls: "n", text: "#" + run.first }),
      el("span", { cls: "time", text: run.time }),
      el("span", { cls: "actor", text: first.actor || D.labels.noActor }),
      el("span", { cls: "text" }, el("i", { cls: "cat", style: "background:" + catVar(first.cat) }), run.text),
      el("span", { cls: "btn", text: opened ? U["run.collapse"] : fmt(U["run.expand"], { count: run.count }) }));
    return li;
  }

  function eventRow(e, sub) {
    var cls = [sub ? "sub" : "", e.root ? "root" : "", state.sel === e.n ? "sel" : ""].join(" ").trim();
    var li = el("li", {
      cls: cls || null, tabindex: "0", "data-n": String(e.n),
      onclick: function () { select(e.n, false); },
      onkeydown: function (ev) { onRowKey(ev, e.n); }
    },
      el("span", { cls: "n", text: "#" + e.n }),
      el("span", { cls: "time", text: e.time }),
      el("span", { cls: "actor", text: e.actor || D.labels.noActor }),
      el("span", { cls: "text" }, el("i", { cls: "cat", style: "background:" + catVar(e.cat) }),
        (e.root ? D.labels.rootMarker + ": " : "") + e.text),
      el("span", { cls: "badge conf-" + e.conf, text: e.confLabel }));
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

  // Selecting from the chart or the verdict may need to open a burst, clear filters that
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
    for (var k in dots) dots[k].setAttribute("class", "dot" + (Number(k) === n ? " sel" : ""));
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
    detailEl.appendChild(el("h2", null,
      el("span", { text: U["detail.title"] + (e ? " #" + e.n : "") }), close));
    if (!e) { detailEl.appendChild(el("p", { cls: "empty", text: U["detail.empty"] })); return; }
    if (e.root) detailEl.appendChild(el("div", { cls: "rootnote", text: U["detail.root"] }));
    detailEl.appendChild(el("p", { cls: "text", text: e.text }));
    var dl = el("dl");
    [[U["detail.basis"], e.time + " (" + e.basis + ")"], [U["detail.phase"], e.phase],
      [U["detail.actor"], e.actor || D.labels.noActor]].forEach(function (p) {
      dl.appendChild(el("dt", { text: p[0] })); dl.appendChild(el("dd", { text: p[1] }));
    });
    dl.appendChild(el("dt", { text: U["detail.confidence"] }));
    dl.appendChild(el("dd", null, el("span", { cls: "badge conf-" + e.conf, text: e.confLabel })));
    detailEl.appendChild(dl);
    if (e.notes.length) {
      detailEl.appendChild(el("h3", { text: U["detail.notes"] }));
      var ul = el("ul");
      e.notes.forEach(function (t) { ul.appendChild(el("li", { text: t })); });
      detailEl.appendChild(ul);
    }
    detailEl.appendChild(el("h3", { text: U["detail.evidence"] }));
    e.cites.forEach(function (i) {
      var c = D.cites[i];
      var btn = el("button", { cls: "btn", text: U.copy });
      btn.addEventListener("click", function () { copy(c.ref + "\n" + c.ex, btn); });
      detailEl.appendChild(el("div", { cls: "cite" },
        el("div", { cls: "ref" }, el("span", { text: c.ref }), btn),
        c.ex ? el("pre", { text: c.ex }) : null));
    });
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
