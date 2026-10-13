"use strict";

// A terminal selection is a rectangle of screen rather than a run of text, so a
// block copied out of indented output carries the depth it happened to be printed
// at. Pasting a YAML fragment that a tool printed inside its own indentation is the
// case that matters: every line lands too deep, and a parser rejects the first key
// it reads. Removing the indentation the whole block shares fixes that, and because
// only the shared part goes, the structure inside the block survives — which is the
// whole of what YAML means.
//
// The margin is compared as text, not counted as characters. A tab and eight spaces
// both look like indentation on screen, and slicing a count measured on one where
// the other stands would quietly change a line's depth instead of preserving it.
function commonMargin(lines) {
  let margin = null;
  for (const line of lines) {
    // A blank line has no indentation to speak of and must not veto the margin: a
    // block with a blank line in the middle is still one indented block.
    if (!line.trim()) continue;
    const indent = (/^[ \t]*/.exec(line) || [""])[0];
    if (margin === null) {
      margin = indent;
      continue;
    }
    let shared = 0;
    while (shared < margin.length && shared < indent.length && margin[shared] === indent[shared]) shared += 1;
    margin = margin.slice(0, shared);
    if (!margin) return "";
  }
  return margin || "";
}

// What goes to the clipboard when a copy is not asked to be verbatim: the shared
// margin removed, and a line the terminal padded out with spaces left empty rather
// than holding whitespace that was never visible.
function cleanCopy(value) {
  const lines = String(value ?? "").replace(/\r/g, "").split("\n");
  const margin = commonMargin(lines);
  return lines
    .map((line) => (line.trim() ? line.slice(margin.length) : ""))
    .join("\n");
}

module.exports = { cleanCopy, commonMargin };
