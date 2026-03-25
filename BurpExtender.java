package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.net.URL;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.util.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @Author: Sai1
 * @Date: 2026/03/25 16:50
 * @Description: Map API Key 泄露检测、流量清洗、被动监听、高亮与综合调试工具
 */
public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IMessageEditorController {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    // UI 组件
    private JPanel mainPanel;
    private JTable keyTable;
    private DefaultTableModel tableModel;
    private JComboBox<String> providerCombo;
    private JComboBox<String> platformCombo;
    private JTextField keyField;
    private JTextField skField;
    private JTextField refererField;
    private JTextField extraField;
    private JButton btnDefaultTest;
    private JButton btnRandomTest;
    private JComboBox<String> regionCombo;
    
    // Burp 原生 HTTP 报文编辑器
    private IMessageEditor requestEditor;
    private IMessageEditor responseEditor;
    private IHttpRequestResponse currentMessage; // 用于提供给 EditorController

    // 占位符常量
    private static final String REFERER_PLACEHOLDER = "例如: https://example.com (绕过前端白名单)";
    private static final String EXTRA_PLACEHOLDER = "例如: mcode=com.app;SHA1";

    // 状态与正则
    private Set<String> uniqueKeys = new HashSet<>();
    private int recordCount = 0;
    private static final Pattern GOOGLE_PATTERN = Pattern.compile("AIza[0-9A-Za-z-_]{35}");
    private static final Pattern AMAP_PATTERN = Pattern.compile("(?i)\\bkey=([a-f0-9]{32})\\b");
    private static final Pattern BAIDU_PATTERN = Pattern.compile("(?i)\\bak=([a-z0-9_-]{32})\\b");
    private static final Pattern TENCENT_PATTERN = Pattern.compile("(?i)\\bkey=([A-Z0-9]{5}(-[A-Z0-9]{5}){5})\\b");

    // 现代浏览器 UA 池
    private static final String[] UA_POOL = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0"
    };

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("MapAPI Leak Debugger V1.0");

        SwingUtilities.invokeLater(this::initGUI);

        callbacks.registerHttpListener(this);
        callbacks.registerContextMenuFactory(this);

        callbacks.printOutput("[*] T00ls MapAPI Leak Debugger...");
        callbacks.printOutput("[+] T00ls MapAPI Leak Debugger Loaded.");
        callbacks.printOutput("-----------------------------------------------\n" + //
                        "MapAPI Leak Debugger V1.0\n" + //
                        "@Author: Sai1\n" + //
                        "@Description: Map API Key 泄露检测、流量清洗、被动监听、高亮与综合调试工具\n" + //
                        "@Github: https://github.com/Th3-SAIl/MapAPI-Leak-Debugger\n" + //
                        "-----------------------------------------------");
    }

    @Override
    public String getTabCaption() {
        return "MapAPI";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    // ==========================================
    // 1. 核心 GUI 构建
    // ==========================================
    private void initGUI() {
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(new EmptyBorder(8, 8, 8, 8));
        
        // --- 顶部：提取列表 ---
        String[] columns = {"#", "来源工具", "目标域名", "服务商猜测", "API Key", "检测结果"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override public boolean isCellEditable(int row, int column) { return false; }
        };
        keyTable = new JTable(tableModel);
        keyTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        keyTable.setRowHeight(24);
        
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);
        for (int i = 0; i < keyTable.getColumnCount(); i++) {
            keyTable.getColumnModel().getColumn(i).setCellRenderer(centerRenderer);
        }
        
        keyTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && keyTable.getSelectedRow() != -1) {
                int row = keyTable.getSelectedRow();
                String provider = (String) tableModel.getValueAt(row, 3);
                String key = (String) tableModel.getValueAt(row, 4);
                keyField.setText(key);
                setProviderComboByString(provider);
            }
        });
        JScrollPane tableScroll = new JScrollPane(keyTable);
        tableScroll.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("被动流量清洗提取列表 (点击记录可直接测试)"),
                new EmptyBorder(5, 5, 5, 5)
        ));

        // --- 底部：调试面板 ---
        JPanel bottomPanel = new JPanel(new BorderLayout(0, 10));
        bottomPanel.setBorder(new EmptyBorder(10, 0, 0, 0));
        
        JPanel configPanel = new JPanel(new GridBagLayout());
        configPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("API 综合调试与滥用探测"),
                new EmptyBorder(10, 10, 10, 10)
        ));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 10, 8, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridy = 0; gbc.gridx = 0; configPanel.add(new JLabel("服务商:"), gbc);
        providerCombo = new JComboBox<>(new String[]{"Amap (高德)", "Baidu (百度)", "Tencent (腾讯)", "Google (谷歌)"});
        gbc.gridx = 1; configPanel.add(providerCombo, gbc);
        
        gbc.gridx = 2; configPanel.add(new JLabel("目标平台:"), gbc);
        platformCombo = new JComboBox<>(new String[]{"Webapi", "Jsapi", "Miniprogram", "Android", "iOS", "HarmonyOS", "LLM"});
        gbc.gridx = 3; configPanel.add(platformCombo, gbc);

        gbc.gridy = 1; gbc.gridx = 0; configPanel.add(new JLabel("API Key:"), gbc);
        gbc.gridx = 1; keyField = new JTextField(30); configPanel.add(keyField, gbc);
        gbc.gridx = 2; configPanel.add(new JLabel("Secret Key:"), gbc);
        gbc.gridx = 3; skField = new JTextField(25); configPanel.add(skField, gbc);

        gbc.gridy = 2; gbc.gridx = 0; configPanel.add(new JLabel("伪造 Referer:"), gbc);
        refererField = new JTextField(); setupPlaceholder(refererField, REFERER_PLACEHOLDER);
        gbc.gridx = 1; configPanel.add(refererField, gbc);
        
        gbc.gridx = 2; configPanel.add(new JLabel("附加参数:"), gbc);
        extraField = new JTextField(); setupPlaceholder(extraField, EXTRA_PLACEHOLDER);
        gbc.gridx = 3; configPanel.add(extraField, gbc);

        gbc.gridy = 3; gbc.gridx = 0; gbc.gridwidth = 4;
        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        btnDefaultTest = new JButton("发送测试");
        regionCombo = new JComboBox<>(new String[]{"China (中国大陆)", "Global (全球)"});
        btnRandomTest = new JButton("随机 ReGeo 逆解析测试");
        
        btnDefaultTest.addActionListener(e -> startTest("default"));
        btnRandomTest.addActionListener(e -> startTest("random"));
        
        actionPanel.add(btnDefaultTest);
        actionPanel.add(new JLabel(" |  随机边界:"));
        actionPanel.add(regionCombo);
        actionPanel.add(btnRandomTest);
        configPanel.add(actionPanel, gbc);

        // --- 核心更新：使用 Burp 原生 IMessageEditor ---
        requestEditor = callbacks.createMessageEditor(this, false);
        responseEditor = callbacks.createMessageEditor(this, false);
        
        JSplitPane ioSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestEditor.getComponent(), responseEditor.getComponent());
        ioSplitPane.setResizeWeight(0.5);

        bottomPanel.add(configPanel, BorderLayout.NORTH);
        bottomPanel.add(ioSplitPane, BorderLayout.CENTER);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, bottomPanel);
        splitPane.setDividerLocation(200);
        splitPane.setResizeWeight(0.2);
        mainPanel.add(splitPane, BorderLayout.CENTER);

        callbacks.addSuiteTab(this);
    }

    private void setupPlaceholder(JTextField field, String placeholder) {
        field.setText(placeholder);
        field.setForeground(Color.GRAY);
        field.addFocusListener(new FocusAdapter() {
            @Override public void focusGained(FocusEvent e) {
                if (field.getText().equals(placeholder)) {
                    field.setText("");
                    field.setForeground(Color.BLACK);
                }
            }
            @Override public void focusLost(FocusEvent e) {
                if (field.getText().isEmpty()) {
                    field.setForeground(Color.GRAY);
                    field.setText(placeholder);
                }
            }
        });
    }

    private void setProviderComboByString(String providerStr) {
        for (int i = 0; i < providerCombo.getItemCount(); i++) {
            if (providerCombo.getItemAt(i).toLowerCase().contains(providerStr.toLowerCase())) {
                providerCombo.setSelectedIndex(i); break;
            }
        }
    }

    // ==========================================
    // 2. 被动流量监听
    // ==========================================
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageInfo == null) return;
        byte[] data = messageIsRequest ? messageInfo.getRequest() : messageInfo.getResponse();
        if (data == null) return;

        String traffic = helpers.bytesToString(data);
        String host = messageInfo.getHttpService().getHost();
        String toolName = callbacks.getToolName(toolFlag);

        extractAndAddToTable(traffic, GOOGLE_PATTERN, "Google", host, toolName, 0, messageInfo);
        extractAndAddToTable(traffic, AMAP_PATTERN, "Amap", host, toolName, 1, messageInfo);
        extractAndAddToTable(traffic, BAIDU_PATTERN, "Baidu", host, toolName, 1, messageInfo);
        extractAndAddToTable(traffic, TENCENT_PATTERN, "Tencent", host, toolName, 1, messageInfo);
    }

    private void extractAndAddToTable(String traffic, Pattern pattern, String provider, String host, String toolName, int groupIndex, IHttpRequestResponse messageInfo) {
        Matcher matcher = pattern.matcher(traffic);
        while (matcher.find()) {
            String key = groupIndex == 0 ? matcher.group(0) : matcher.group(groupIndex);
            if (uniqueKeys.add(key)) {
                SwingUtilities.invokeLater(() -> {
                    recordCount++;
                    tableModel.addRow(new Object[]{recordCount, toolName, host, provider, key, "待测试"});
                });
                messageInfo.setHighlight("red");
                messageInfo.setComment("MapAPI Key Found: " + provider);
            }
        }
    }

    // ==========================================
    // 3. IMessageEditorController 接口实现
    // ==========================================
    @Override
    public IHttpService getHttpService() {
        return currentMessage != null ? currentMessage.getHttpService() : null;
    }

    @Override
    public byte[] getRequest() {
        return currentMessage != null ? currentMessage.getRequest() : null;
    }

    @Override
    public byte[] getResponse() {
        return currentMessage != null ? currentMessage.getResponse() : null;
    }

    // ==========================================
    // 4. 核心网络请求与结果回写
    // ==========================================
    private void updateTableResult(String targetKey, String resultText) {
        SwingUtilities.invokeLater(() -> {
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                if (targetKey.equals(tableModel.getValueAt(i, 4))) {
                    tableModel.setValueAt(resultText, i, 5);
                }
            }
        });
    }

    private String getRandomUserAgent() {
        return UA_POOL[new Random().nextInt(UA_POOL.length)];
    }

    private void startTest(String action) {
        String key = keyField.getText().trim();
        if (key.isEmpty()) return;

        String provider = ((String) providerCombo.getSelectedItem()).split(" ")[0].trim().toLowerCase();
        String platform = ((String) platformCombo.getSelectedItem()).toLowerCase();
        String sk = skField.getText().trim();
        
        String referer = refererField.getText().equals(REFERER_PLACEHOLDER) ? "" : refererField.getText().trim();
        String extra = extraField.getText().equals(EXTRA_PLACEHOLDER) ? "" : extraField.getText().trim();
        String region = ((String) regionCombo.getSelectedItem()).split(" ")[0].trim().toLowerCase();

        // 重置 Editor 视图
        SwingUtilities.invokeLater(() -> {
            requestEditor.setMessage(new byte[0], true);
            responseEditor.setMessage(new byte[0], false);
        });
        
        btnDefaultTest.setEnabled(false); btnRandomTest.setEnabled(false);

        double[] coords = null;
        if (action.equals("random")) coords = generateRandomGeo(region);

        final double[] finalCoords = coords;
        final String finalReferer = referer;
        final String finalExtra = extra;

        updateTableResult(key, "测试中...");

        new Thread(() -> {
            try {
                executeRequest(provider, platform, key, sk, finalReferer, finalExtra, action, finalCoords);
            } catch (Exception ex) {
                updateTableResult(key, "请求异常");
            } finally {
                SwingUtilities.invokeLater(() -> {
                    btnDefaultTest.setEnabled(true); btnRandomTest.setEnabled(true);
                });
            }
        }).start();
    }

    private void executeRequest(String provider, String platform, String key, String sk, String referer, String extra, String action, double[] coords) {
        String targetUrl = "";
        Map<String, String> params = new LinkedHashMap<>();

        if (provider.equals("amap")) {
            if (action.equals("default")) {
                if (Arrays.asList("webapi", "miniprogram", "llm").contains(platform)) {
                    targetUrl = "https://restapi.amap.com/v3/geocode/geo";
                    params.put("address", "北京市"); params.put("key", key);
                } else if (platform.equals("jsapi")) {
                    targetUrl = "https://webapi.amap.com/maps"; params.put("v", "2.0"); params.put("key", key);
                } else {
                    targetUrl = "https://restapi.amap.com/v3/ip"; params.put("key", key);
                }
            } else {
                targetUrl = "https://restapi.amap.com/v3/geocode/regeo";
                params.put("location", coords[0] + "," + coords[1]); params.put("key", key); params.put("extensions", "all");
            }
        } 
        else if (provider.equals("baidu")) {
            if (action.equals("default")) {
                if (Arrays.asList("webapi", "miniprogram", "llm").contains(platform)) {
                    targetUrl = "https://api.map.baidu.com/geocoding/v3/";
                    params.put("address", "北京市"); params.put("output", "json"); params.put("ak", key);
                    if (!sk.isEmpty()) params.put("sn", calcBaiduSN("/geocoding/v3/", params, sk));
                } else if (platform.equals("jsapi")) {
                    targetUrl = "https://api.map.baidu.com/api"; params.put("v", "3.0"); params.put("ak", key);
                } else {
                    targetUrl = "https://api.map.baidu.com/location/ip";
                    params.put("ak", key); params.put("coor", "bd09ll");
                    if (!extra.isEmpty()) params.put("mcode", extra);
                }
            } else {
                targetUrl = "https://api.map.baidu.com/reverse_geocoding/v3/";
                params.put("location", coords[1] + "," + coords[0]); 
                params.put("ak", key); params.put("output", "json"); params.put("coordtype", "wgs84ll");
                if (!extra.isEmpty()) params.put("mcode", extra);
                if (!sk.isEmpty()) params.put("sn", calcBaiduSN("/reverse_geocoding/v3/", params, sk));
            }
        }
        else if (provider.equals("tencent")) {
            if (action.equals("default")) {
                if (Arrays.asList("webapi", "miniprogram", "llm").contains(platform)) {
                    targetUrl = "https://apis.map.qq.com/ws/geocoder/v1/";
                    params.put("address", "北京市"); params.put("key", key);
                    if (!sk.isEmpty()) params.put("sig", calcTencentSIG("/ws/geocoder/v1/", params, sk));
                } else if (platform.equals("jsapi")) {
                    targetUrl = "https://map.qq.com/api/gljs"; params.put("v", "1.exp"); params.put("key", key);
                } else {
                    targetUrl = "https://apis.map.qq.com/ws/location/v1/ip"; params.put("key", key);
                }
            } else {
                targetUrl = "https://apis.map.qq.com/ws/geocoder/v1/";
                params.put("location", coords[1] + "," + coords[0]); params.put("key", key); params.put("get_poi", "1");
                if (!sk.isEmpty()) params.put("sig", calcTencentSIG("/ws/geocoder/v1/", params, sk));
            }
        }
        else if (provider.equals("google")) {
            if (action.equals("default")) {
                if (platform.equals("jsapi")) {
                    targetUrl = "https://maps.googleapis.com/maps/api/js"; params.put("key", key);
                } else {
                    targetUrl = "https://maps.googleapis.com/maps/api/geocode/json";
                    params.put("address", "Mountain View, CA"); params.put("key", key);
                }
            } else {
                targetUrl = "https://maps.googleapis.com/maps/api/geocode/json";
                params.put("latlng", coords[1] + "," + coords[0]); params.put("key", key);
            }
        }

        sendBurpNativeRequest(targetUrl, params, platform, referer, provider, key);
    }

    private void sendBurpNativeRequest(String baseUrl, Map<String, String> params, String platform, String referer, String provider, String currentKey) {
        try {
            // 解析主机信息
            URL url = new URL(baseUrl);
            int port = url.getPort() == -1 ? (url.getProtocol().equalsIgnoreCase("https") ? 443 : 80) : url.getPort();
            IHttpService httpService = helpers.buildHttpService(url.getHost(), port, url.getProtocol());

            // 拼接参数
            StringBuilder query = new StringBuilder();
            for (Map.Entry<String, String> entry : params.entrySet()) {
                if (query.length() > 0) query.append("&");
                query.append(entry.getKey()).append("=").append(URLEncoder.encode(entry.getValue(), "UTF-8"));
            }
            String pathAndQuery = url.getFile() + "?" + query.toString();

            // 构造原生 Header 列表
            List<String> headers = new ArrayList<>();
            headers.add("GET " + pathAndQuery + " HTTP/1.1");
            headers.add("Host: " + url.getHost());
            
            String userAgent = getRandomUserAgent();
            if (platform.equals("miniprogram")) {
                userAgent = "Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36 MicroMessenger/8.0.30.2260";
                headers.add("Referer: " + (referer.isEmpty() ? "https://servicewechat.com/wx_test_appid_123/0/page-frame.html" : referer));
            } else if (platform.equals("jsapi") && !referer.isEmpty()) {
                headers.add("Referer: " + referer);
            }
            headers.add("User-Agent: " + userAgent);
            headers.add("Accept: application/json, text/plain, */*");
            headers.add("Connection: close");

            // 构建原生请求体
            byte[] requestBytes = helpers.buildHttpMessage(headers, null);
            
            // 先在 UI 显示请求包
            SwingUtilities.invokeLater(() -> requestEditor.setMessage(requestBytes, true));

            // 调用 Burp 底层核心引擎发起真实网络请求 (支持代理走通)
            IHttpRequestResponse reqRes = callbacks.makeHttpRequest(httpService, requestBytes);
            currentMessage = reqRes; // 更新当前报文，服务于 ContextMenu
            
            // 渲染原生响应包
            SwingUtilities.invokeLater(() -> {
                if (reqRes.getResponse() != null) {
                    responseEditor.setMessage(reqRes.getResponse(), false);
                }
            });

            // 进行漏洞规则强校验
            if (reqRes.getResponse() != null) {
                IResponseInfo respInfo = helpers.analyzeResponse(reqRes.getResponse());
                int status = respInfo.getStatusCode();
                
                // 提取 HTTP Body
                int bodyOffset = respInfo.getBodyOffset();
                byte[] responseBytes = reqRes.getResponse();
                String responseBody = helpers.bytesToString(Arrays.copyOfRange(responseBytes, bodyOffset, responseBytes.length));

                boolean isVulnerable = false;
                if (status == 200) {
                    String rb = responseBody.replaceAll("\\s+", ""); 
                    if (provider.equals("amap")) {
                        if (rb.contains("\"status\":\"1\"") && rb.contains("\"infocode\":\"10000\"")) isVulnerable = true;
                    } else if (provider.equals("baidu") || provider.equals("tencent")) {
                        if (rb.contains("\"status\":0")) isVulnerable = true;
                    } else if (provider.equals("google")) {
                        if (rb.contains("\"status\":\"OK\"")) isVulnerable = true;
                    }
                }

                if (isVulnerable) {
                    updateTableResult(currentKey, "🚨 存在滥用");
                } else if (status >= 400 || responseBody.contains("error_message") || responseBody.contains("\"status\":\"0\"") || responseBody.contains("USERKEY_PLAT_NOMATCH")) {
                    updateTableResult(currentKey, "拦截/校验失败");
                } else {
                    updateTableResult(currentKey, "安全");
                }
            } else {
                updateTableResult(currentKey, "请求超时/无响应");
            }

        } catch (Exception e) {
            updateTableResult(currentKey, "请求异常");
        }
    }

    // ==========================================
    // 5. 右键菜单与其他辅助算法
    // ==========================================
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menu = new ArrayList<>();
        int[] bounds = invocation.getSelectionBounds();
        if (bounds != null && bounds[0] != bounds[1]) {
            JMenuItem item = new JMenuItem("发送至 MapAPI Tester");
            item.addActionListener(e -> {
                byte context = invocation.getInvocationContext();
                IHttpRequestResponse reqRes = invocation.getSelectedMessages()[0];
                byte[] data = (context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST || 
                               context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) 
                               ? reqRes.getRequest() : reqRes.getResponse();
                
                String selectedKey = helpers.bytesToString(data).substring(bounds[0], bounds[1]).trim();
                SwingUtilities.invokeLater(() -> {
                    keyField.setText(selectedKey);
                    if (selectedKey.startsWith("AIza") && selectedKey.length() == 39) setProviderComboByString("google");
                    else if (selectedKey.matches("[A-Z0-9]{5}(-[A-Z0-9]{5}){5}")) setProviderComboByString("tencent");
                    else if (selectedKey.length() == 32) setProviderComboByString("amap");
                });
            });
            menu.add(item);
        }
        return menu;
    }

    private double[] generateRandomGeo(String region) {
        Random rand = new Random();
        double lng = region.equals("china") ? 73.33 + (135.05 - 73.33) * rand.nextDouble() : -180.0 + 360.0 * rand.nextDouble();
        double lat = region.equals("china") ? 18.00 + (53.33 - 18.00) * rand.nextDouble() : -90.0 + 180.0 * rand.nextDouble();
        return new double[]{Math.round(lng * 1000000.0) / 1000000.0, Math.round(lat * 1000000.0) / 1000000.0};
    }

    private String calcBaiduSN(String path, Map<String, String> params, String sk) {
        try {
            List<String> keys = new ArrayList<>(params.keySet()); Collections.sort(keys);
            StringBuilder qs = new StringBuilder();
            for (String key : keys) { if (qs.length() > 0) qs.append("&"); qs.append(key).append("=").append(params.get(key)); }
            return md5(URLEncoder.encode(path + "?" + qs.toString() + sk, "UTF-8"));
        } catch (Exception e) { return ""; }
    }

    private String calcTencentSIG(String path, Map<String, String> params, String sk) {
        List<String> keys = new ArrayList<>(params.keySet()); Collections.sort(keys);
        StringBuilder qs = new StringBuilder();
        for (String key : keys) { if (qs.length() > 0) qs.append("&"); qs.append(key).append("=").append(params.get(key)); }
        return md5(path + "?" + qs.toString() + sk);
    }

    private String md5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] array = md.digest(input.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : array) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) { return ""; }
    }
}