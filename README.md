# pairwise-sandbox-policy

容器宿主机要收紧密码沙箱，策略检查器却给不出可信结论：seccomp 默认动作是 SCMP_ACT_ALLOW，只列了少量 deny 就等于没限制；syscall 参数过滤只比较低 32 位，指针和标志位被忽略；AppArmor profile 的 include 没有递归解析，被引用的规则实际没生效；capabilities 用字符串包含判断，CAP_NET_RAW 和 CAP_NET_BIND_SERVICE 混淆；子进程继承和 no_new_privs 没有检查。security/sandbox_policy.py 是核心，tests/test_sandbox_policy.py 15个红。要修的是：默认拒绝；参数全量比较；include 展开；capability 集合；继承与提权约束。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：其他；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
