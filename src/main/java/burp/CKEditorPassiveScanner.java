	/* ================= Design & Developed By Masoud Zivari(code5ecure)============ */
	/* ================= Passive CKEditor4 & CKEditor5 Detection (Version 3.0) ==== */
	package burp;
	import burp.api.montoya.BurpExtension;
	import burp.api.montoya.MontoyaApi;
	import burp.api.montoya.scanner.AuditResult;
	import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
	import burp.api.montoya.scanner.scancheck.ScanCheckType;
	import burp.api.montoya.http.message.HttpRequestResponse;
	import burp.api.montoya.scanner.audit.issues.AuditIssue;
	import static burp.api.montoya.scanner.audit.issues.AuditIssueConfidence.CERTAIN;
	import static burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.INFORMATION;

	import java.util.*;
	import java.util.concurrent.ConcurrentHashMap;
	import java.util.concurrent.ConcurrentSkipListSet;
	import java.util.regex.Matcher;
	import java.util.regex.Pattern;
	public class CKEditorPassiveScanner implements BurpExtension {
		private MontoyaApi api;
		private static final int MAX_PATHS_PER_HOST = 100;
		private final ConcurrentHashMap<String, ConcurrentSkipListSet<String>> ckeditorPathsPerHost =
				new ConcurrentHashMap<>();
		private final ConcurrentHashMap<String, ConcurrentSkipListSet<String>> pluginsPerHost =
				new ConcurrentHashMap<>();
		
		private final ConcurrentHashMap<String, Integer> lastPluginCountPerHost =
				new ConcurrentHashMap<>();
		private final ConcurrentHashMap<String, String> lastBasePathPerHost =
				new ConcurrentHashMap<>();

		private static final Pattern CKEDITOR4_VERSION =
				Pattern.compile("CKEDITOR\\.version\\s*=\\s*['\"]([0-9.]+)['\"]");
		private static final Pattern CKEDITOR5_MARKER =
				Pattern.compile("ClassicEditor|InlineEditor|BalloonEditor|DecoupledEditor");
		private static final Pattern CKEDITOR_JS_CSS =
				Pattern.compile("([^\"'\\s>]*ckeditor[^\"'\\s>]*\\.(js|css))", Pattern.CASE_INSENSITIVE);
		private static final Pattern HTML_TEXTAREA =
				Pattern.compile("<textarea[^>]+class=['\"]ckeditor['\"]", Pattern.CASE_INSENSITIVE);
		private static final Pattern CKEDITOR_KEYWORD =
				Pattern.compile("\\bckeditor\\b", Pattern.CASE_INSENSITIVE);
		private static final Pattern DATA_CKEDITOR_PATH =
				Pattern.compile("data-[^=]*ckeditor[^=]*=['\"]([^'\"]+)['\"]", Pattern.CASE_INSENSITIVE);
		private static final Pattern PLUGIN_PATTERN =
				Pattern.compile("plugins/([a-zA-Z0-9_-]+)/");
		private static final Pattern CONFIG_PLUGINS_PATTERN =
				Pattern.compile("(extraPlugins|removePlugins|plugins)\\s*[:=]\\s*['\"]([^'\"]+)['\"]?", Pattern.CASE_INSENSITIVE);
		private static final Pattern CKEDITOR_ANY_REFERENCE =
				Pattern.compile("['\"]([^'\"]*ckeditor[^'\"]*?)['\"]", Pattern.CASE_INSENSITIVE);

		private class CKEditorPassiveCheck implements PassiveScanCheck {
			private final MontoyaApi api;
			CKEditorPassiveCheck(MontoyaApi api) {
				this.api = api;
			}
			@Override
			public String checkName() {
				return "CKEditor Passive Detection";
			}
			@Override
			public AuditResult doCheck(HttpRequestResponse baseRequestResponse) {
				String host = baseRequestResponse.request().httpService().host();
				String reqPath = baseRequestResponse.request().pathWithoutQuery();

				String normReqPath = normalizePath(reqPath);
				if (!normReqPath.isEmpty()) {
					addCkPath(host, normReqPath);
				}

			   if (!baseRequestResponse.hasResponse() || baseRequestResponse.response().statusCode() != 200) {
					return AuditResult.auditResult();
				}

				// --- Content-Type guard: skip binary assets before touching the body at all ---
				String contentType = baseRequestResponse.response().headerValue("Content-Type");
				if (contentType == null) {
					return AuditResult.auditResult();
				}
				String ctLower = contentType.toLowerCase();
				boolean isTextLike = ctLower.contains("text/")
						|| ctLower.contains("application/javascript")
						|| ctLower.contains("application/x-javascript")
						|| ctLower.contains("application/json");
				if (!isTextLike) {
					return AuditResult.auditResult();
				}

	if (ckeditorPathsPerHost.size() > 1000) {
		ckeditorPathsPerHost.clear();
		pluginsPerHost.clear();
		lastPluginCountPerHost.clear();
		lastBasePathPerHost.clear();
	}
	   
	


			   String body;

	try {
		body = baseRequestResponse.response().bodyToString();

		if (body.length() > 2_000_000) {
			api.logging().logToOutput("CKEditor scanner: Body too large on "
					+ baseRequestResponse.request().url());
			return AuditResult.auditResult();
		}

	} catch (Exception e) {
		api.logging().logToError("CKEditor scanner: Body parsing error on "
				+ baseRequestResponse.request().url() + " → " + e.getMessage());
		return AuditResult.auditResult();
	}

				String ckType = "CKEditor (Generic)";
				String version = "Unknown";
				String signature = "ckeditor keyword";

				String lowerBody = body.toLowerCase();
				String lowerPath = reqPath.toLowerCase();

				if (!lowerBody.contains("ckeditor") && !lowerPath.contains("ckeditor")) {
					return AuditResult.auditResult();
				}

				Matcher v4 = CKEDITOR4_VERSION.matcher(body);
				
				if (v4.find()) {
					version = v4.group(1);
					ckType = "CKEditor 4";
					signature = "CKEDITOR.version = '" + version + "'";
				}
				if (CKEDITOR5_MARKER.matcher(body).find()) {
					ckType = "CKEditor 5";
					signature = "ClassicEditor / InlineEditor / ... marker";
					version = "5.x";
				}
				if (HTML_TEXTAREA.matcher(body).find()) {
					ckType = "CKEditor (textarea class)";
					signature = "<textarea class=\"ckeditor\"";
				}

				boolean hasCk = CKEDITOR_KEYWORD.matcher(body).find() ||
								CKEDITOR_JS_CSS.matcher(body).find() ||
								DATA_CKEDITOR_PATH.matcher(body).find() ||
								lowerPath.contains("ckeditor");

				if (!hasCk) {
					return AuditResult.auditResult();
				}

				Matcher jsCssMatcher = CKEDITOR_JS_CSS.matcher(body);
				while (jsCssMatcher.find()) {
					String fullPath = resolveRelativePath(reqPath, jsCssMatcher.group(1));
					addCkPath(host, fullPath);
				}
				Matcher dataPathMatcher = DATA_CKEDITOR_PATH.matcher(body);
				while (dataPathMatcher.find()) {
					String fullPath = resolveRelativePath(reqPath, dataPathMatcher.group(1));
					addCkPath(host, fullPath);
				}
				Matcher anyRefMatcher = CKEDITOR_ANY_REFERENCE.matcher(body);
				while (anyRefMatcher.find()) {
					String raw = anyRefMatcher.group(1);
					String lowerRaw = raw.toLowerCase();
					if (lowerRaw.contains("ckeditor") &&
						(raw.contains("/") || raw.endsWith(".js") || raw.endsWith(".css") || raw.startsWith("/"))) {
						String fullPath = resolveRelativePath(reqPath, raw);
						addCkPath(host, fullPath);
					}
				}

				String requestPathLower = reqPath.toLowerCase();
			   if (requestPathLower.endsWith("config.js")) {
		Set<String> configPlugins = extractPluginsFromConfig(body);

		pluginsPerHost
				.computeIfAbsent(host, k -> new ConcurrentSkipListSet<>())
				.addAll(configPlugins);

		
		ConcurrentSkipListSet<String> pluginSet = pluginsPerHost.get(host);
		if (pluginSet != null && pluginSet.size() > 100) {
			Iterator<String> it = pluginSet.iterator();
			while (pluginSet.size() > 100 && it.hasNext()) {
				it.next();
				it.remove();
			}
		}
	}

				Set<String> plugins = new TreeSet<>();
				Matcher pluginM = PLUGIN_PATTERN.matcher(body);
				while (pluginM.find()) {
					plugins.add(pluginM.group(1));
				}
				ConcurrentSkipListSet<String> hostPlugins = pluginsPerHost.get(host);
				if (hostPlugins != null) {
					plugins.addAll(hostPlugins);
				}

				String basePath = calculateBasePath(host);

			   
				int prevPluginCount = lastPluginCountPerHost.getOrDefault(host, 0);
				String prevBasePath = lastBasePathPerHost.getOrDefault(host, "Unknown");
				boolean hasNewEvidence = (plugins.size() > prevPluginCount) || !basePath.equals(prevBasePath);

				if (!hasNewEvidence) {
					return AuditResult.auditResult();  
				}

			   
				lastPluginCountPerHost.put(host, plugins.size());
				lastBasePathPerHost.put(host, basePath);

				List<String> evidences = new ArrayList<>();
	int evidenceCounter = 1;

	evidences.add("Evidence #" + (evidenceCounter++) + ": Current response – CKEditor type: " + ckType 
				  + " | Version: " + version + " | Signature: " + signature);

	if (!plugins.isEmpty()) {
		evidences.add("Evidence #" + (evidenceCounter++) + ": Plugins detected in this response/config.js: " 
					  + String.join(", ", plugins));
	}

	if (!basePath.equals("Unknown")) {
		evidences.add("Evidence #" + (evidenceCounter++) + ": Base Path calculated from collected paths: " + basePath);
	}

	if (requestPathLower.endsWith("config.js")) {
		evidences.add("Evidence #" + (evidenceCounter++) + ": This request is config.js – extra plugins extracted directly from it.");
	}

	
	String detailHtml = "<b>CKEditor Detected</b><br><br>" +
			"<ul>" +
			"<li><b>Type:</b> " + escapeHtml(ckType) + "</li>" +
			"<li><b>Version:</b> " + escapeHtml(version) + "</li>" +
			"<li><b>Signature:</b> " + escapeHtml(signature) + "</li>" +
			"<li><b>Base Path:</b> " + escapeHtml(basePath) + "</li>";

	detailHtml += "<li><b>Collected Evidences (" + (evidenceCounter-1) + " items):</b><ul>";
	for (String ev : evidences) {
		String safeEv = escapeHtml(ev);
		detailHtml += "<li>" + safeEv + "</li>";
	}
	detailHtml += "</ul></li>";

	if (!plugins.isEmpty()) {
		List<String> safePlugins = new ArrayList<>();
		for (String p : plugins) {
			safePlugins.add(escapeHtml(p));
		}
		detailHtml += "<li><b>All Plugins (from config.js):</b> " + String.join(", ", safePlugins) + "</li>";
	} else {
		detailHtml += "<li><b>Plugins:</b> None detected</li>";
	}
	detailHtml += "</ul>";

				String background = "CKEditor is a popular WYSIWYG editor. Older versions or misconfigured plugins may allow XSS or file upload vulnerabilities.";
				String remediation = "The presence of CKEditor may increase the application's attack surface depending on configuration. Ensure it is up to date and only necessary plugins are enabled.";

				AuditIssue issue = AuditIssue.auditIssue(
						"CKEditor Detected",
						detailHtml,
						remediation,
						baseRequestResponse.request().url(),
						INFORMATION,
						CERTAIN,
						background,
						null,
						null,
						baseRequestResponse
				);
				return AuditResult.auditResult(issue);
			}
		}

		@Override
		public void initialize(MontoyaApi api) {
			this.api = api;
			api.extension().setName("CKEditor Passive Scanner V2.0");
			api.scanner().registerPassiveScanCheck(
					new CKEditorPassiveCheck(api),
					ScanCheckType.PER_REQUEST
			);
			
			
		}

		private String calculateBasePath(String host) {
			ConcurrentSkipListSet<String> paths = ckeditorPathsPerHost.get(host);
			if (paths == null || paths.isEmpty()) {
				return "Unknown";
			}
			String first = paths.first();
			String last = paths.last();
			int minLen = Math.min(first.length(), last.length());
			int commonLen = 0;
			for (int i = 0; i < minLen; i++) {
				if (first.charAt(i) == last.charAt(i)) {
					commonLen++;
				} else {
					break;
				}
			}
			String commonPrefix = first.substring(0, commonLen);
			int lastSlash = commonPrefix.lastIndexOf('/');
			return (lastSlash >= 0) ? commonPrefix.substring(0, lastSlash + 1) : commonPrefix + "/";
		}

		private String normalizePath(String raw) {
			if (raw == null) return "";
			String p = raw;
			if (p.startsWith("http")) {
				int idx = p.indexOf("/", p.indexOf("//") + 2);
				if (idx != -1) p = p.substring(idx);
			}
			p = p.split("[?#]")[0];
			return p;
		}

		private String resolveRelativePath(String requestPath, String relativePath) {
			if (relativePath == null || relativePath.trim().isEmpty()) return "";
			String rel = normalizePath(relativePath);
			if (rel.startsWith("/")) {
				return rel;
			}
			String dir = requestPath.isEmpty() ? "/" : requestPath;
			if (!dir.endsWith("/")) {
				int last = dir.lastIndexOf('/');
				if (last >= 0) {
					dir = dir.substring(0, last + 1);
				} else {
					dir = "/";
				}
			}
			if (dir.endsWith("/") && rel.startsWith("/")) {
				rel = rel.substring(1);
			}
			return dir + rel;
		}

		private void addCkPath(String host, String path) {
			if (path.isEmpty()) return;
			String lower = path.toLowerCase();
			if (!lower.contains("ckeditor") && !lower.endsWith("config.js") && !lower.endsWith("ckeditor.js")) {
				return;
			}
			ckeditorPathsPerHost
					.computeIfAbsent(host, k -> new ConcurrentSkipListSet<>())
					.add(path);
			ConcurrentSkipListSet<String> set = ckeditorPathsPerHost.get(host);
			if (set != null && set.size() > MAX_PATHS_PER_HOST) {
				Iterator<String> it = set.iterator();
				while (set.size() > MAX_PATHS_PER_HOST && it.hasNext()) {
					it.next();
					it.remove();
				}
			}
		}

		private Set<String> extractPluginsFromConfig(String body) {
			Set<String> plugs = new TreeSet<>();
			if (body == null || body.isEmpty()) return plugs;
			Matcher m = CONFIG_PLUGINS_PATTERN.matcher(body);
			while (m.find()) {
				String list = m.group(2);
				if (list != null && !list.isEmpty()) {
					for (String p : list.split("[,\\s;]+")) {
						String trimmed = p.trim().replaceAll("^['\"]+|['\"]+$", "");
						if (!trimmed.isEmpty() && trimmed.length() > 1) {
							plugs.add(trimmed);
						}
					}
				}
			}
			Matcher pm = PLUGIN_PATTERN.matcher(body);
			while (pm.find()) {
				plugs.add(pm.group(1));
			}
			return plugs;
		}

		/**
		 * Escapes HTTP-derived strings before they are embedded into the Burp
		 * Advisory panel's HTML detail field, preventing HTML/markup injection
		 * from attacker-controlled response content (e.g. plugin names, paths,
		 * version strings).
		 */
		private String escapeHtml(String s) {
			if (s == null) return "";
			return s.replace("&", "&amp;")
					.replace("<", "&lt;")
					.replace(">", "&gt;")
					.replace("\"", "&quot;");
		}
	}
	// This is CKEDITOR 4 &5 passive scanner by Masoud Zivari(code5ecure).
