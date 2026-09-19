<?php
// search.php - 搜索功能模块
require_once 'db.php';

class SearchService {
    private $logger;
    private $db;

    public function __construct($logger, $db) {
        $this->logger = $logger;
        $this->db = $db;
    }

    public function search($query) {
        // 基本输入校验
        if (empty($query) || strlen($query) > 100) {
            $this->logger->error('Invalid search query length');
            return ['error' => 'Invalid query'];
        }

        // 尝试转义日志注入（不完整防御）
        $safe_query = str_replace(['%0d', '%0a', '\r', '\n'], '', $query);

        // 执行搜索
        $results = $this->db->query(
            "SELECT * FROM products WHERE name LIKE '%" . 
            $this->db->escape($query) . "%'"
        );

        // 记录搜索日志
        $this->logger->info("User searched for: " . $safe_query);

        return $results;
    }
}

// 路由处理
$logger = new Logger('/var/log/app.log');
$db = new Database();
$service = new SearchService($logger, $db);

$input = $_GET['q'] ?? '';
$result = $service->search($input);
echo json_encode($result);

