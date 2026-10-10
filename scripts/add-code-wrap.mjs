// 为内容文章里的围栏代码块批量追加 `wrap` 元数据（Expressive Code 自动换行）
// 规则（与手写示例一致）：
//   ```            -> ```text wrap
//   ```http        -> ```http wrap
//   ```http a="b"  -> ```http a="b" wrap
// 已含 wrap 的块保持不变；mermaid 块与缩进的嵌套块默认跳过。
// 用法： node scripts/add-code-wrap.mjs [--apply] [--include-mermaid]
import fs from "node:fs";
import path from "node:path";

const APPLY = process.argv.includes("--apply");
const INCLUDE_MERMAID = process.argv.includes("--include-mermaid");
const ROOT = "src/content";

const files = [];
(function walk(dir) {
	for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
		if (entry.name.startsWith(".")) continue; // 跳过 .obsidian 等
		const full = path.join(dir, entry.name);
		if (entry.isDirectory()) walk(full);
		else if (/\.mdx?$/.test(entry.name)) files.push(full);
	}
})(ROOT);

const FENCE_RE = /^(\s*)(`{3,}|~{3,})(.*)$/;

const summary = {
	scanned: files.length,
	fences: 0,
	changed: 0,
	alreadyWrap: 0,
	skippedMermaid: 0,
	indented: 0,
	skippedTilde: 0,
	langs: {},
	metaSamples: [],
};

const report = [];

for (const file of files) {
	const raw = fs.readFileSync(file, "utf8");
	const eol = raw.includes("\r\n") ? "\r\n" : "\n";
	const lines = raw.split(/\r?\n/);
	let openFence = null; // { char, len }
	let inFrontmatter = lines[0]?.trim() === "---";
	let dirty = false;

	for (let i = 0; i < lines.length; i++) {
		const line = lines[i];
		if (i === 0 && inFrontmatter) continue;
		if (inFrontmatter) {
			if (line.trim() === "---") inFrontmatter = false;
			continue;
		}
		if (openFence) {
			// 闭合围栏：同类字符、长度不小于开始围栏、除空白外无其他内容
			const close = line.match(FENCE_RE);
			if (
				close &&
				close[2][0] === openFence.char &&
				close[2].length >= openFence.len &&
				close[3].trim() === ""
			) {
				openFence = null;
			}
			continue;
		}
		const m = line.match(FENCE_RE);
		if (!m) continue;
		const indent = m[1];
		const fence = m[2];
		const info = m[3].trim();
		openFence = { char: fence[0], len: fence.length };
		summary.fences++;

		if (indent.length > 0) {
			summary.indented++;
		}
		if (fence[0] === "~") {
			summary.skippedTilde++;
			continue;
		}
		const tokens = info.length ? info.split(/\s+/) : [];
		const lang = tokens[0] ?? "";
		summary.langs[lang || "(none)"] =
			(summary.langs[lang || "(none)"] ?? 0) + 1;

		if (tokens.includes("wrap")) {
			summary.alreadyWrap++;
			continue;
		}
		if (lang === "mermaid" && !INCLUDE_MERMAID) {
			summary.skippedMermaid++;
			continue;
		}
		if (tokens.length > 1 && summary.metaSamples.length < 25) {
			summary.metaSamples.push(`${file.replace(/\\/g, "/")}:${i + 1}  ${info}`);
		}

		const nextInfo = lang ? `${info} wrap` : "text wrap";
		lines[i] = `${indent}${fence}${nextInfo}`;
		dirty = true;
		summary.changed++;
		if (report.length < 20) {
			report.push(
				`  ${file.replace(/\\/g, "/")}:${i + 1}  ${line.trim()}  ->  ${lines[i].trim()}`,
			);
		}
	}

	if (dirty && APPLY) {
		fs.writeFileSync(file, lines.join(eol), "utf8");
	}
}

console.log(`模式: ${APPLY ? "APPLY（已写入）" : "DRY-RUN（未写入）"}`);
console.log(`扫描文件: ${summary.scanned}  围栏代码块: ${summary.fences}`);
console.log(
	`需追加 wrap: ${summary.changed}  已有 wrap: ${summary.alreadyWrap}  跳过 mermaid: ${summary.skippedMermaid}  其中缩进块: ${summary.indented}  跳过 ~~~: ${summary.skippedTilde}`,
);
console.log("\n语言分布(按出现次数):");
for (const [lang, n] of Object.entries(summary.langs).sort(
	(a, b) => b[1] - a[1],
)) {
	console.log(`  ${lang.padEnd(16)} ${n}`);
}
if (summary.metaSamples.length) {
	console.log("\n带额外元数据的代码块示例（需确认 wrap 追加位置）:");
	for (const s of summary.metaSamples) console.log(`  ${s}`);
}
if (report.length) {
	console.log("\n变更示例:");
	for (const r of report) console.log(r);
}
