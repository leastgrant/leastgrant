/*
 * Everything interactive on leastgrant.xyz.
 *
 * Constraints this file works under, all of them deliberate:
 *
 *   - No `innerHTML`, no `insertAdjacentHTML`, no `document.write`, no `eval`,
 *     no `new Function`, no dynamic <script>. Text goes in through
 *     `textContent`. There is no code path here that turns a string into
 *     markup, so there is no code path that turns a string into script.
 *   - Nothing here is required to read the page. Every state this script can
 *     produce is already in the HTML when it arrives; the script only reveals,
 *     hides and replays. Turn JavaScript off and the terminal shows a finished
 *     session, the decision walkthrough shows its first example, and the
 *     install command is still selectable.
 *   - No network. Nothing is fetched, measured, or reported. The page makes
 *     exactly the requests the HTML declares and not one more.
 *   - `prefers-reduced-motion` skips straight to the end state rather than
 *     playing a faster version of the animation.
 */

(function () {
  'use strict';

  var reduceMotion = false;
  try {
    reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  } catch (e) {
    /* matchMedia is ancient; if it is missing, animate. */
  }

  // --- the hero terminal ----------------------------------------------------
  //
  // The markup already contains the finished session. Replaying it means
  // hiding the lines, then bringing them back: command lines a character at a
  // time, output lines all at once, because that is how a terminal behaves.

  function initTerminal(root) {
    var lines = Array.prototype.slice.call(root.querySelectorAll('[data-line]'));
    if (!lines.length) return;

    // Capture the finished text before touching anything, so a replay can
    // always get back to it even if a previous run was interrupted.
    var original = lines.map(function (el) {
      return el.getAttribute('data-type') === 'cmd' ? el.textContent : null;
    });

    var caret = document.createElement('span');
    caret.className = 'caret';

    var timers = [];
    var running = false;

    function clearTimers() {
      for (var i = 0; i < timers.length; i++) clearTimeout(timers[i]);
      timers = [];
    }

    function at(ms, fn) {
      timers.push(setTimeout(fn, ms));
    }

    function finish() {
      clearTimers();
      running = false;
      if (caret.parentNode) caret.parentNode.removeChild(caret);
      for (var i = 0; i < lines.length; i++) {
        if (original[i] !== null) lines[i].textContent = original[i];
        lines[i].removeAttribute('hidden');
      }
      root.removeAttribute('data-running');
    }

    // The first exchange is never hidden.
    //
    // Hiding everything and typing from empty means the first thing a visitor
    // sees is a large blank rectangle for as long as the first line takes --
    // which is a poor trade for an animation nobody asked for. Leaving the
    // opening command and its verdict on screen means the terminal is
    // legible at the first frame and the replay still tells the story.
    var SEED = 3; // command, output, spacer

    function play(fromStart) {
      if (running) finish();
      running = true;
      root.setAttribute('data-running', '');
      clearTimers();

      var begin = fromStart ? 0 : SEED;
      for (var i = begin; i < lines.length; i++) {
        lines[i].setAttribute('hidden', '');
        if (original[i] !== null) lines[i].textContent = '';
      }

      var clock = fromStart ? 120 : 420;

      lines.slice(begin).forEach(function (el, offset) {
        var index = begin + offset;
        var isCommand = original[index] !== null;

        if (!isCommand) {
          at(clock, function () {
            el.removeAttribute('hidden');
          });
          // Output lands in a block. A short beat after it reads as the tool
          // thinking, which it is: the parse happens before the verdict.
          clock += el.textContent.trim() ? 340 : 60;
          return;
        }

        var text = original[index];
        at(clock, function () {
          el.removeAttribute('hidden');
          el.appendChild(caret);
        });

        // 15ms a character. Slower reads better but the whole session is time the
        // visitor spends looking at a box that is still filling up, so it is kept short.
        for (var c = 0; c < text.length; c++) {
          (function (n) {
            at(clock + 60 + n * 15, function () {
              el.textContent = text.slice(0, n + 1);
              el.appendChild(caret);
            });
          })(c);
        }
        clock += 60 + text.length * 15 + 170;
      });

      at(clock + 200, function () {
        if (caret.parentNode) caret.parentNode.removeChild(caret);
        running = false;
        root.removeAttribute('data-running');
      });
    }

    var replay = document.querySelector('[data-replay]');
    if (replay) {
      replay.removeAttribute('hidden');
      // An explicit replay starts from nothing, because that is what the
      // reader asked for by pressing it.
      replay.addEventListener('click', function () {
        play(true);
      });
    }

    if (reduceMotion) return;

    // Only start once the terminal is actually on screen. Autoplaying an
    // animation the reader has scrolled past is just wasted work.
    if (typeof IntersectionObserver === 'function') {
      var seen = false;
      var io = new IntersectionObserver(
        function (entries) {
          for (var i = 0; i < entries.length; i++) {
            if (entries[i].isIntersecting && !seen) {
              seen = true;
              io.disconnect();
              play();
            }
          }
        },
        { threshold: 0.25 },
      );
      io.observe(root);
    } else {
      play();
    }
  }

  // --- the decision walkthrough --------------------------------------------
  //
  // Every example's full state is already in the document, one panel each.
  // Switching example is showing one panel and hiding the rest -- no state is
  // computed in the browser, which is the only way to promise that what the
  // page shows is what the engine returned at build time.

  function initGauntlet(root) {
    var buttons = Array.prototype.slice.call(root.querySelectorAll('[data-pick]'));
    var panels = Array.prototype.slice.call(root.querySelectorAll('[data-panel]'));
    if (!buttons.length || !panels.length) return;

    function select(id) {
      for (var i = 0; i < panels.length; i++) {
        var match = panels[i].getAttribute('data-panel') === id;
        if (match) panels[i].removeAttribute('hidden');
        else panels[i].setAttribute('hidden', '');
      }
      for (var j = 0; j < buttons.length; j++) {
        buttons[j].setAttribute('aria-pressed', buttons[j].getAttribute('data-pick') === id ? 'true' : 'false');
      }

      if (reduceMotion) return;

      // Restart the top-to-bottom sweep down the gates. Removing the attribute,
      // forcing a reflow and putting it back is the standard way to replay a
      // CSS animation without touching inline styles -- which a strict
      // style-src would block anyway.
      var gates = root.querySelector('[data-panel="' + cssEscape(id) + '"] .gates');
      if (gates) {
        gates.removeAttribute('data-run');
        void gates.offsetWidth;
        gates.setAttribute('data-run', '');
      }
    }

    buttons.forEach(function (button) {
      button.addEventListener('click', function () {
        select(button.getAttribute('data-pick'));
      });
    });

    // The panels are all visible without JavaScript, stacked, which is a
    // legible fallback but not the intended reading. Collapse to the first now
    // that we can switch between them.
    var first = buttons[0].getAttribute('data-pick');
    root.setAttribute('data-enhanced', '');
    select(first);
  }

  /** Minimal CSS.escape: these ids are build-generated slugs. */
  function cssEscape(value) {
    return String(value).replace(/[^a-zA-Z0-9_-]/g, '');
  }

  // --- copy buttons ---------------------------------------------------------

  function initCopy(button) {
    var targetId = button.getAttribute('data-copy');
    var source = document.getElementById(targetId);
    if (!source) return;

    button.removeAttribute('hidden');
    var idle = button.textContent;
    var timer = null;

    button.addEventListener('click', function () {
      var text = (source.getAttribute('data-clipboard') || source.textContent || '').trim();

      function done(ok) {
        button.textContent = ok ? 'copied' : 'select it';
        button.setAttribute('data-done', ok ? 'true' : 'false');
        if (timer) clearTimeout(timer);
        timer = setTimeout(function () {
          button.textContent = idle;
          button.removeAttribute('data-done');
        }, 1800);
      }

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(
          function () {
            done(true);
          },
          function () {
            done(false);
          },
        );
        return;
      }

      // No clipboard API, or an insecure context. Select the text so the
      // reader can copy it themselves rather than leaving them with a button
      // that silently does nothing.
      try {
        var range = document.createRange();
        range.selectNodeContents(source);
        var sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        done(false);
      } catch (e) {
        done(false);
      }
    });
  }

  // --- boot -----------------------------------------------------------------

  function boot() {
    var term = document.querySelector('[data-term-demo]');
    if (term) initTerminal(term);

    var gauntlet = document.querySelector('[data-gauntlet]');
    if (gauntlet) initGauntlet(gauntlet);

    var copies = document.querySelectorAll('[data-copy]');
    for (var i = 0; i < copies.length; i++) initCopy(copies[i]);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
