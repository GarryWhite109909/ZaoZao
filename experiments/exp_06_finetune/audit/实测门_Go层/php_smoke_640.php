<?php
// search.php - 搜索用户功能
require_once 'db.php';
require_once 'session.php';

class UserSearch {
    private $db;
    
    public function __construct($db) {
        $this->db = $db;
    }
    
    public function search($keyword) {
        // 基础过滤：替换危险字符（防御迷惑）
        $keyword = str_replace(['"', "'", '\\', ';', '#', '--'], '', $keyword);
        
        // 检查是否包含LDAP特殊前缀（防御迷惑）
        if (strpos($keyword, '*') !== false || strpos($keyword, '(') !== false) {
            // 简单拒绝，但未处理编码后的变体
            if (preg_match('/[()*]/', $keyword)) {
                return ['error' => '非法输入'];
            }
        }
        
        // 构建LDAP查询（sink）
        $filter = "(|(uid=" . $keyword . ")(cn=" . $keyword . "))";
        
        $ds = ldap_connect("ldap://localhost");
        ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);
        $bind = ldap_bind($ds, "cn=admin,dc=example,dc=com", "secret");
        
        $sr = ldap_search($ds, "ou=people,dc=example,dc=com", $filter);
        $entries = ldap_get_entries($ds, $sr);
        
        ldap_close($ds);
        return $entries;
    }
}

// 处理请求
session_start();
if (!isset($_SESSION['user'])) {
    http_response_code(403);
    die('Forbidden');
}

$keyword = $_GET['q'] ?? '';
if (empty($keyword)) {
    die('Missing parameter');
}

$search = new UserSearch(new Database());
$result = $search->search($keyword);

header('Content-Type: application/json');
echo json_encode($result);
?>

