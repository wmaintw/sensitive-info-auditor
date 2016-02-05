# sensitive-info-auditor

使用说明：

Step 1. pull代码到本地

Step 2. 配置：在`src/main/resources/` 目录下新建3个txt文件，分别命名为:

- `github-accounts.txt`，被检查的github账号，一行一条记录
- `sensitive-words.txt`，高级别敏感词，一行一条记录
- `sensitive-words-general.txt`，常规敏感词，一行一条记录
- `oauth-token.txt`，调用github api需要用到access token，可以在github账号的设置里自助生成，将准备好的access token放到这个文件里的第一行

Step 3. 运行命令执行检查：在项目根目录，执行以下命令`gradle run`

Step 4. 检查报告：每扫描完一个github账号，都会生成一份对应的报告，位置在根目录的`scan-report`目录里


**注：**

由于github api限制了请求速率，一个账号每小时的请求不能超过5000次，再加上有众多repos需要检查，因此会花费比较长的时间才能完成（经验数据：需要大约3～4小时才能完成100个github账号的检查）。
这种情况下，可以通过以下命令让程序持续运行，并且把console输出保存起来：

`nohup gradle run > log/application.log &`
