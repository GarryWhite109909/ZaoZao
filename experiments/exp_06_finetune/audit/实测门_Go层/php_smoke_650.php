<?php
// src/Controller/TemplateController.php
// 场景：用户上传模板文件后，通过模板引擎渲染输出

class TemplateController {
    private $templateDir;
    private $cacheDir;

    public function __construct($templateDir, $cacheDir) {
        $this->templateDir = $templateDir;
        $this->cacheDir = $cacheDir;
    }

    // 处理模板渲染请求
    public function renderTemplate($request, $response) {
        // 从请求中获取模板名称和用户数据
        $templateName = $request->get('template');
        $userData = $request->get('data');

        // 防御：过滤路径，防止路径穿越
        $templateName = str_replace('../', '', $templateName);
        $templateName = str_replace('..\\', '', $templateName);

        // 检查文件是否存在
        $templatePath = $this->templateDir . '/' . $templateName . '.php';
        if (!file_exists($templatePath)) {
            return $response->json(['error' => 'Template not found'], 404);
        }

        // 从缓存中读取，若无则编译模板
        $cacheKey = md5($templateName . serialize($userData));
        $cacheFile = $this->cacheDir . '/' . $cacheKey . '.cache';

        if (file_exists($cacheFile)) {
            $compiledTemplate = file_get_contents($cacheFile);
        } else {
            // 编译模板：将用户数据嵌入模板代码
            $templateContent = file_get_contents($templatePath);
            $compiledTemplate = $this->compileTemplate($templateContent, $userData);
            file_put_contents($cacheFile, $compiledTemplate);
        }

        // 执行编译后的模板代码（关键点）
        eval($compiledTemplate);
        return $response->json(['status' => 'rendered']);
    }

    // 编译模板：简单替换占位符
    private function compileTemplate($templateContent, $userData) {
        // 防御：将用户数据中的危险字符转义
        $userData = array_map(function($value) {
            return str_replace(['<?', '?>', '<?php'], '', $value);
        }, $userData);

        // 将模板中的 {key} 替换为用户数据
        $compiled = $templateContent;
        foreach ($userData as $key => $value) {
            $compiled = str_replace('{' . $key . '}', $value, $compiled);
        }
        return $compiled;
    }
}

// 使用示例（模拟请求）
$controller = new TemplateController('/var/www/templates', '/var/www/cache');
$request = (object)['template' => 'welcome', 'data' => ['name' => 'Alice', 'color' => 'blue']];
$response = new stdClass();
$response->json = function($data, $code = 200) { echo json_encode($data) . "\n"; };
$controller->renderTemplate($request, $response);
?>

