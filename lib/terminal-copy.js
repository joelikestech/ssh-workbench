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
//
// `startColumn` is the screen column the selection began at. A drag usually starts
// on the first character of a command rather than in the space before it, so the
// first line arrives with no indentation at all; measured as text, it would share
// none with the lines below and nothing would be removed from any of them. Counted
// at the column it really stands in, it shares the margin it visibly has. Only the
// margin is ever removed: nothing is added to a line that started mid-row.
//
// `column` says the selection was a rectangle (Alt+drag) rather than a run of text.
// Then every line was cut at the same screen column, not only the first, so they all
// stand at `startColumn` alike and none of them needs counting from further left.
// Padding only the first one out would make it look deeper than lines that sat
// exactly as deep on screen, and the block would come out with its first line
// indented and the rest flush.
function cleanCopy(value, { startColumn = 0, column = false } = {}) {
  const lines = String(value ?? "").replace(/\r/g, "").split("\n");
  const lead = column ? 0 : Math.max(0, Math.floor(Number(startColumn) || 0));
  const measured = lead && lines[0].trim() ? [" ".repeat(lead) + lines[0], ...lines.slice(1)] : lines;
  const margin = commonMargin(measured);
  return lines
    .map((line, index) => {
      if (!line.trim()) return "";
      return index === 0 && lead ? line.slice(Math.max(0, margin.length - lead)) : line.slice(margin.length);
    })
    .join("\n");
}

// Pasted text is typed into the remote shell, so a control character inside it acts
// as one. ESC is the dangerous one: with bracketed paste on, the shell treats
// everything between ESC [200~ and ESC [201~ as text rather than as commands, and a
// clipboard that carries its own ESC [201~ ends that early -- whatever follows it
// arrives as typing, and a CR in it runs it. Copying from a web page or a chat
// window is enough to put one there. So every C0 control except tab, LF and CR, DEL,
// and every C1 control is taken out before the text reaches the terminal, the way
// other terminals do. Tab, LF and CR stay because they are what pasted lines and
// indentation are made of.
function cleanPaste(value) {
  return String(value ?? "").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, "");
}

module.exports = { cleanCopy, commonMargin, cleanPaste };
