/* ================= Design & Developed By Masoud Zivari(code5ecure)============ */
/* ================= Passive CKEditor4 & CKEditor5 Detection (Final) ============ */

package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler; 
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import static burp.api.montoya.scanner.audit.issues.AuditIssueConfidence.CERTAIN;
import static burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.INFORMATION;
import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;



public class CKEditorPassiveScanner implements BurpExtension, HttpHandler {

    private MontoyaApi api;
    private static final int MAX_ENTRIES = 2000;

    private final Map<String, Set<String>> observedCkeditorPaths = new ConcurrentHashMap<>();

    private final Map<String, Set<String>> pluginInfoPerUrl =
            Collections.synchronizedMap(new LinkedHashMap<>() {
                protected boolean removeEldestEntry(Map.Entry<String, Set<String>> eldest) {
                    return size() > MAX_ENTRIES;
                }
            });

    private final Map<String, HttpRequest> requestPerUrl =
            Collections.synchronizedMap(new LinkedHashMap<>() {
                protected boolean removeEldestEntry(Map.Entry<String, HttpRequest> eldest) {
                    return size() > MAX_ENTRIES;
                }
            });

    private DefaultTableModel detectionModel;
    private JTextArea detailsArea;

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

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("CKEditor Passive Scanner 4.0 (Final)");

        detectionModel = new DefaultTableModel(
                new Object[]{"Host", "Type", "Version", "Signature", "URL", "Base Path"}, 0) {
            public boolean isCellEditable(int r, int c) { return false; }
        };

        JTable table = new JTable(detectionModel);
        table.setRowSorter(new TableRowSorter<>(detectionModel));

        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int row = table.getSelectedRow();
            if (row == -1) return;

            int modelRow = table.convertRowIndexToModel(row);
            String url = detectionModel.getValueAt(modelRow, 4).toString();
            HttpRequest req = requestPerUrl.get(url);

            StringBuilder sb = new StringBuilder();
            sb.append("URL: ").append(url).append("\n");
            sb.append("Host: ").append(detectionModel.getValueAt(modelRow, 0)).append("\n");
            sb.append("Type: ").append(detectionModel.getValueAt(modelRow, 1)).append("\n");
            sb.append("Version: ").append(detectionModel.getValueAt(modelRow, 2)).append("\n");
            sb.append("Signature: ").append(detectionModel.getValueAt(modelRow, 3)).append("\n");
            sb.append("Base Path: ").append(detectionModel.getValueAt(modelRow, 5)).append("\n\n");

            Set<String> plugins = pluginInfoPerUrl.get(url);
            if (plugins != null && !plugins.isEmpty()) {
                sb.append("Plugins:\n");
                plugins.forEach(p -> sb.append(" - ").append(p).append("\n"));
                sb.append("\n");
            }

            if (req != null) {
                sb.append("Request:\n");
                sb.append(req.toString());
            }

            detailsArea.setText(sb.toString());
            detailsArea.setCaretPosition(0);
        });

        JPopupMenu popup = new JPopupMenu();
        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        popup.add(sendToRepeater);

        sendToRepeater.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row == -1) return;
            int modelRow = table.convertRowIndexToModel(row);
            String url = detectionModel.getValueAt(modelRow, 4).toString();
            HttpRequest req = requestPerUrl.get(url);
            if (req != null) {
                api.repeater().sendToRepeater(req);
            }
        });

        table.setComponentPopupMenu(popup);

        JTextField filterField = new JTextField(20);
        filterField.getDocument().addDocumentListener(new DocumentListener() {
            private void update() {
                String t = filterField.getText();
                ((TableRowSorter<?>) table.getRowSorter())
                        .setRowFilter(t.isEmpty() ? null :
                                RowFilter.regexFilter("(?i)" + Pattern.quote(t)));
            }
            public void insertUpdate(DocumentEvent e) { update(); }
            public void removeUpdate(DocumentEvent e) { update(); }
            public void changedUpdate(DocumentEvent e) { update(); }
        });

        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> {
            detectionModel.setRowCount(0);
            observedCkeditorPaths.clear();
            pluginInfoPerUrl.clear();
            requestPerUrl.clear();
            detailsArea.setText("");
        });

        detailsArea = new JTextArea();
        detailsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        detailsArea.setEditable(false);

        JSplitPane split = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table),
                new JScrollPane(detailsArea)
        );
        split.setResizeWeight(0.65);

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(new JLabel("Filter:"));
        top.add(filterField);
        top.add(clearButton);

        JPanel main = new JPanel(new BorderLayout());
        main.add(top, BorderLayout.NORTH);
        main.add(split, BorderLayout.CENTER);

        api.userInterface().registerSuiteTab("CKEditor Scanner", main);
        api.http().registerHttpHandler(this);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        if (CKEDITOR_KEYWORD.matcher(req.path()).find()) {
            recordPath(req.httpService().host(), req.path());
        }
        return RequestToBeSentAction.continueWith(req);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived res) {
        if (res.body() == null) return ResponseReceivedAction.continueWith(res);

        String body = new String(res.body().getBytes(), StandardCharsets.UTF_8);
        HttpRequest req = res.initiatingRequest();
        String host = req.httpService().host();
        String url = req.url();

        Matcher jsCss = CKEDITOR_JS_CSS.matcher(body);
        while (jsCss.find()) recordPath(host, jsCss.group(1));

        Matcher dataPath = DATA_CKEDITOR_PATH.matcher(body);
        while (dataPath.find()) recordPath(host, dataPath.group(1));

        if (CKEDITOR4_VERSION.matcher(body).find())
            add(host, "CKEditor 4", "Detected", "CKEDITOR.version", url, res);

        if (CKEDITOR5_MARKER.matcher(body).find())
            add(host, "CKEditor 5", "Detected", "CKEditor 5 marker", url, res);

        if (HTML_TEXTAREA.matcher(body).find())
            add(host, "CKEditor (HTML)", "Unknown", "textarea class=ckeditor", url, res);

        Matcher plugin = PLUGIN_PATTERN.matcher(body);
        while (plugin.find()) {
            pluginInfoPerUrl.computeIfAbsent(url, u -> new TreeSet<>())
                    .add(plugin.group(1));
        }

        if (CKEDITOR_KEYWORD.matcher(body).find())
            add(host, "CKEditor (Generic)", "Unknown", "ckeditor keyword present", url, res);

        return ResponseReceivedAction.continueWith(res);
    }

    private void recordPath(String host, String raw) {
        if (raw == null) return;

        String p = raw;
        if (p.startsWith("http")) {
            int i = p.indexOf("/", p.indexOf("//") + 2);
            if (i != -1) p = p.substring(i);
        }
        p = p.split("[?#]")[0];

        if (!p.toLowerCase().contains("ckeditor")) return;

        observedCkeditorPaths
                .computeIfAbsent(host, h -> ConcurrentHashMap.newKeySet())
                .add(p);
    }

    private String calculateBasePath(String host) {
        Set<String> paths = observedCkeditorPaths.get(host);
        if (paths == null || paths.isEmpty()) return "Unknown";

        for (String p : paths) {
            int idx = p.toLowerCase().indexOf("/ckeditor");
            if (idx >= 0) {
                return p.substring(0, idx + "/ckeditor".length()) + "/";
            }
        }
        return "Unknown";
    }

    private void add(String host, String type, String version,
                     String sig, String url, HttpResponseReceived res) {
        
        HttpRequest req = res.initiatingRequest();
        
        SwingUtilities.invokeLater(() -> {
            detectionModel.addRow(new Object[]{
                    host, type, version, sig, url, calculateBasePath(host)
            });
            requestPerUrl.put(url, req);
        });

       
        String basePath = calculateBasePath(host);
        String detail = "<b>CKEditor Detected</b><br><br>" +
                "<ul>" +
                "<li><b>Type:</b> " + type + "</li>" +
                "<li><b>Version:</b> " + version + "</li>" +
                "<li><b>Signature:</b> " + sig + "</li>" +
                "<li><b>Base Path:</b> " + basePath + "</li>" +
                "</ul>";
        
        String remediation = "Ensure that the CKEditor installation is updated to the latest secure version. " +
                    "Review the configuration of any file upload plugins (e.g., CKFinder, KCFinder) to prevent unrestricted file uploads.";

        String background = "CKEditor is a popular open-source WYSIWYG text editor. While generally secure, older versions or misconfigured plugins " +
                    "can introduce vulnerabilities such as Cross-Site Scripting (XSS) or Unrestricted File Uploads.";

       
        
        AuditIssue issue = AuditIssue.auditIssue(
            "CKEditor Detected",
            detail,
            remediation,
            url,
            INFORMATION,
            CERTAIN,
            background,
            null,
            INFORMATION,
            HttpRequestResponse.httpRequestResponse(req, res)
        );

        api.siteMap().add(issue);
    }
}

// This is CKEDITOR 4 &5  passive scanner by Masoud Zivari(code5ecure).
