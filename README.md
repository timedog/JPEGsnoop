# JPEGsnoop-avitool v0.0.2

`avitool`是一款用于AVI（MJPG）文件解析的工具，它对整个文件的合法性进行检查，并收集信息存储在sqlite数据库中

## 特性
- AVI文件结构完整性检查
- MJPG数据有效性检查，`avitool`通过解码每一帧MJPG来检查数据正确与否
- INDEX数据有效性检查，检查各个字段正确性、MOVI段与INDEX是否有未对应的情况
- 生成AVI文件结构的树状图
- 记录AVI文件的信息到数据库中，方便后续分析（分析帧率变化、码率变化等）

## 快照
<img src="https://github.com/timedog/JPEGsnoop/blob/JPEGSnoop-avitool/jpegsnoop-avitool-0.png">
<img src="https://github.com/timedog/JPEGsnoop/blob/JPEGSnoop-avitool/jpegsnoop-avitool-1.png">