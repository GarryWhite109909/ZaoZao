<?php
// Pattern reference: CVE-2021-24288 —— 模式参考(非该 CVE 的官方归因;标签基于代码形态)。原形态:SQL injection in shortcode
// Real pattern: shortcode attribute concatenated into SQL query

class WPCode_Query {
    private $wpdb;

    public function __construct($wpdb) {
        $this->wpdb = $wpdb;
    }

    public function get_codes_by_category($atts) {
        $category = isset($atts['category']) ? $atts['category'] : '';
        $limit = isset($atts['limit']) ? intval($atts['limit']) : 10;

        if (empty($category)) {
            return array();
        }

        // Vulnerable: $category from shortcode attribute concatenated into SQL
        $query = "SELECT p.ID, p.post_title, p.post_content
                  FROM {$this->wpdb->posts} p
                  INNER JOIN {$this->wpdb->term_relationships} tr ON p.ID = tr.object_id
                  INNER JOIN {$this->wpdb->term_taxonomy} tt ON tr.term_taxonomy_id = tt.term_taxonomy_id
                  WHERE p.post_type = 'wpcode'
                  AND tt.taxonomy = 'wpcode_category'
                  AND tt.term_id IN (SELECT term_id FROM {$this->wpdb->terms} WHERE name = '" . $category . "')
                  ORDER BY p.post_date DESC
                  LIMIT " . $limit;

        $results = $this->wpdb->get_results($query, ARRAY_A);
        return $results;
    }
}

// Usage: [wpcode_list category="user_provided" limit="10"]
$plugin = new WPCode_Query($wpdb);
echo json_encode($plugin->get_codes_by_category($_GET));
?>
