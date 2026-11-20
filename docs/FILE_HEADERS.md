# JUN 文件头使用说明

VS Code 已配置 `junheader` 代码片段。新建文件后先选择语言模式，再输入 `junheader` 并选择补全项；也可打开命令面板，执行“代码片段: 使用代码片段填充文件”（Snippets: Fill File with Snippet），选择 JUN 文件头。

文件名和当天日期自动填入，作者为 JUN，版本采用当前工作区版本。按 Tab 依次填写文件功能、用途、注意事项。代码片段不会监听文件保存，也不会自动更新修改日期；后续修改应维护修改日期和版本。

模板同时安装在当前工作区 `.vscode/jun-header.code-snippets` 和当前 Windows 用户 VS Code 的 `User/snippets/jun-header.code-snippets`。其他工作区可使用用户级模板；当前工作区如果同时出现同名候选，选择任意一个即可。

支持 Python、JavaScript/React、TypeScript、C/C++、Java、C#、Go、Rust、HTML/XML、CSS、SQL、PowerShell、Shell、BAT、Dockerfile、CMake、YAML 和 TOML 对应的注释格式。JSON 不允许注释，不添加文件头。

已有文件通过 `python scripts/file_headers.py --apply` 批量补充；不带参数只统计。工具排除虚拟环境、依赖、第三方库、运行数据、备份、发布包和构建产物，保留原编码 BOM、换行符、shebang、Python 编码声明、XML 声明、HTML doctype 和 Docker 解析指令。

首次批量处理使用本地文件创建时间填写生成日期，并以实际处理日期填写修改日期；本地创建时间不等于原始开发日期。工具为每次变更在 `runtime/file-headers/时间戳/` 保存原文件及校验清单。已有 JUN 文件头不会重复添加。

功能说明按模块名称及所属项目生成，复杂模块后续可补充更具体的说明。版本发布时需要同步更新模板内版本。既有语法错误会记录在清单中，本工具只处理注释，不修复原有业务代码。
