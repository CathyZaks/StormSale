import { describe, it, expect } from "vitest";
import {
  WHITELIST_CONFIG,
  WHITELIST_TAGS,
  WHITELIST_ATTRS,
  sanitizeContent,
  sanitizeMarkdown,
  getSanitizedHtml,
  parseBasicMarkdown,
} from "../utils/security";

describe("Global XSS & Content Sanitization Suite (#78)", () => {
  describe("Whitelist Configuration", () => {
    it("should define strict allowed tags and attributes", () => {
      expect(WHITELIST_CONFIG.ALLOWED_TAGS).toBeDefined();
      expect(WHITELIST_CONFIG.ALLOWED_ATTR).toBeDefined();
      expect(WHITELIST_TAGS).toContain("p");
      expect(WHITELIST_TAGS).toContain("strong");
      expect(WHITELIST_TAGS).toContain("a");
      expect(WHITELIST_TAGS).toContain("code");
      expect(WHITELIST_ATTRS).toContain("href");
      expect(WHITELIST_ATTRS).toContain("title");
    });

    it("should explicitly forbid script, iframe, and dangerous event handlers", () => {
      expect(WHITELIST_CONFIG.FORBID_TAGS).toContain("script");
      expect(WHITELIST_CONFIG.FORBID_TAGS).toContain("iframe");
      expect(WHITELIST_CONFIG.FORBID_TAGS).toContain("object");
      expect(WHITELIST_CONFIG.FORBID_ATTR).toContain("onerror");
      expect(WHITELIST_CONFIG.FORBID_ATTR).toContain("onload");
    });
  });

  describe("sanitizeContent", () => {
    it("should handle empty or falsy inputs gracefully", () => {
      expect(sanitizeContent("")).toBe("");
      expect(sanitizeContent(null as unknown as string)).toBe("");
      expect(sanitizeContent(undefined as unknown as string)).toBe("");
    });

    it("should strip malicious script tags completely", () => {
      const malicious = '<p>Safe</p><script>alert("XSS")</script>';
      const result = sanitizeContent(malicious);
      expect(result).not.toContain("<script");
      expect(result).not.toContain("alert");
      expect(result).toContain("<p>Safe</p>");
    });

    it("should strip inline event handlers", () => {
      const malicious = '<b onclick="stealCookies()" onmouseover="evil()">Click</b>';
      const result = sanitizeContent(malicious);
      expect(result).not.toContain("onclick");
      expect(result).not.toContain("onmouseover");
      expect(result).not.toContain("stealCookies");
      expect(result).toContain("Click");
    });

    it("should strip javascript: pseudo-protocols in links", () => {
      const malicious = '<a href="javascript:alert(document.cookie)">Malicious Link</a>';
      const result = sanitizeContent(malicious);
      expect(result).not.toContain("javascript:");
      expect(result).toContain("Malicious Link");
    });

    it("should strip disallowed elements like iframe and embed", () => {
      const malicious = '<iframe src="https://evil.com"></iframe><embed src="evil.swf">';
      const result = sanitizeContent(malicious);
      expect(result).not.toContain("<iframe");
      expect(result).not.toContain("<embed");
    });

    it("should preserve allowed whitelist tags and attributes", () => {
      const safe = '<p class="lead">Hello <strong>World</strong> and <a href="https://stellar.org" title="Stellar">Stellar</a></p>';
      const result = sanitizeContent(safe);
      expect(result).toContain("<p");
      expect(result).toContain("<strong>World</strong>");
      expect(result).toContain('href="https://stellar.org"');
    });

    it("should use fallback sanitizer when DOMPurify is not supported", () => {
      const originalIsSupported = (DOMPurify as unknown as { isSupported: boolean }).isSupported;
      try {
        (DOMPurify as unknown as { isSupported: boolean }).isSupported = false;
        const html = '<p class="lead">Hello <strong>World</strong><script>alert(1)</script><style>body{}</style><iframe src="x"></iframe><object data="x"></object><embed src="x"><a href="javascript:void(0)" onclick="evil()">link</a><custom>tag</custom><br /></p>';
        const sanitized = sanitizeContent(html);
        expect(sanitized).not.toContain("<script");
        expect(sanitized).not.toContain("alert");
        expect(sanitized).not.toContain("<style");
        expect(sanitized).not.toContain("<iframe");
        expect(sanitized).not.toContain("<object");
        expect(sanitized).not.toContain("<embed");
        expect(sanitized).not.toContain("onclick");
        expect(sanitized).not.toContain("javascript:");
        expect(sanitized).not.toContain("<custom");
        expect(sanitized).toContain("Hello");
        expect(sanitized).toContain("<strong>World</strong>");
      } finally {
        (DOMPurify as unknown as { isSupported: boolean }).isSupported = originalIsSupported;
      }
    });
  });

  describe("sanitizeMarkdown & parseBasicMarkdown", () => {
    it("should handle empty or falsy markdown gracefully", () => {
      expect(sanitizeMarkdown("")).toBe("");
      expect(sanitizeMarkdown(null as unknown as string)).toBe("");
    });

    it("should parse all markdown header levels", () => {
      expect(parseBasicMarkdown("# H1")).toContain("<h1>H1</h1>");
      expect(parseBasicMarkdown("## H2")).toContain("<h2>H2</h2>");
      expect(parseBasicMarkdown("### H3")).toContain("<h3>H3</h3>");
      expect(parseBasicMarkdown("#### H4")).toContain("<h4>H4</h4>");
      expect(parseBasicMarkdown("##### H5")).toContain("<h5>H5</h5>");
      expect(parseBasicMarkdown("###### H6")).toContain("<h6>H6</h6>");
    });

    it("should convert markdown bold, italics, code, and links to safe HTML", () => {
      const markdown = "Here is **bold** and __bold2__ text and *italic* and _italic2_ with `code` and ```block code``` and [Docs](https://example.com)";
      const sanitized = sanitizeMarkdown(markdown);
      expect(sanitized).toContain("<strong>bold</strong>");
      expect(sanitized).toContain("<strong>bold2</strong>");
      expect(sanitized).toContain("<em>italic</em>");
      expect(sanitized).toContain("<em>italic2</em>");
      expect(sanitized).toContain("<code>code</code>");
      expect(sanitized).toContain("<pre><code>block code</code></pre>");
      expect(sanitized).toContain('href="https://example.com"');
    });

    it("should neutralize injected scripts embedded in markdown input", () => {
      const attack = "# Heading\n<script>window.location='https://attacker.com'</script>\n**bold content**";
      const sanitized = sanitizeMarkdown(attack);
      expect(sanitized).not.toContain("<script");
      expect(sanitized).not.toContain("attacker.com");
      expect(sanitized).toContain("<h1>Heading</h1>");
      expect(sanitized).toContain("<strong>bold content</strong>");
    });
  });

  describe("getSanitizedHtml", () => {
    it("should produce __html object suitable for React dangerouslySetInnerHTML", () => {
      const output = getSanitizedHtml("<strong>Safe Text</strong>");
      expect(output).toEqual({ __html: "<strong>Safe Text</strong>" });
    });

    it("should correctly handle markdown flag", () => {
      const output = getSanitizedHtml("**Bold Markdown**", true);
      expect(output.__html).toContain("<strong>Bold Markdown</strong>");
    });
  });
});