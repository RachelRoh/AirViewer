# Ellisys LE Audio Viewer

Ellisys Bluetooth Analyzer에서 내보낸 CSV로 CIS/BIS 링크를 점검하는 단일 HTML 도구.

air log에서 주로 보는 네 가지를 자동으로 찾아준다.

1. Central은 보냈는데 Peripheral이 응답하지 않은 경우
2. 패킷이 깨진 경우 (재전송으로 복구됐는지, 결국 손실됐는지)
3. Payload가 유의미한 데이터로 채워졌는지 (Null PDU, 길이 이상, 전부 0)
4. Event Counter 또는 Subevent를 건너뛴 경우

## 사용법

1. `ellisys_viewer.html`을 브라우저에서 열기 (더블클릭)
2. Ellisys에서 .btt를 열고 Overview를 CSV로 Export
3. CSV 파일을 드래그&드롭하거나 Browse로 로드
4. 파일이 없으면 "Generate Sample Data"로 먼저 확인 가능

> 설치 불필요, 인터넷 불필요. 파일 하나로 동작하고 데이터는 외부로 전송되지 않음.

### Export 시 넣을 컬럼

검사는 CSV에 있는 컬럼에 따라 자동으로 켜지고 꺼진다. Overview에 아래 컬럼을 추가한 뒤 Export하면 모든 검사가 동작한다.

> CIS ID(또는 BIS ID), CIG ID(또는 BIG Handle), Direction, Event Counter, Subevent, SN, NESN, NPI, CRC/Status, Payload Length, Payload(hex), Channel, RSSI, Timestamp

컬럼이 없어 검사할 수 없으면 Issues 탭 카드에 "필요 컬럼: SN, NESN"처럼 이유가 표시된다.

**정해진 포맷이 필요하지는 않다.** 컬럼 순서와 개수는 자유롭고, 컬럼은 이름으로 자동 인식한다. 이름이나 값 표기가 예상과 달라도 상단 **Columns** 버튼에서 직접 맞출 수 있다 (아래 [Column Mapping](#column-mapping) 참고).

---

## 화면 구성

```
┌ Stream Bar ─ CIS/BIS 버튼으로 스트림 표시/숨김 (모든 탭에 적용)
├ Issues        ─ 4가지 검사 결과 요약 (첫 화면)
├ Packet Table  ─ 원본 패킷 + 파생 컬럼, 이슈 간 이동
└ Timeline      ─ ISO Event Grid 외 3개 모드
```

### Stream Bar

- 스트림별 버튼을 클릭해 표시/숨김. 모든 탭에 즉시 반영된다.
- CIG(BIG)가 2개 이상인 캡처에서는 스트림을 `CIG/CIS`로 구분한다. 예: `0x00/0x01`. CIS ID가 CIG마다 반복될 수 있기 때문이다.
- 색상: 스트림마다 고유 색. **C→P는 진한 색, P→C는 연한 색.**

---

### Tab 1: Issues

**검사 카드**: 검사별 건수. 클릭하면 아래 목록이 그 검사로 걸러진다.

**매트릭스**: 행은 스트림×방향, 열은 아래 항목이다.

| 열 | 의미 |
|---|---|
| 전달률 | 오디오 SDU가 전달된 이벤트 비율 = (첫 전송 성공 + 재전송 후 성공) / (전달 + 손실). 마우스를 올리면 내역 표시 |
| 최대 연속 손실 | 연속으로 손실된 이벤트 수의 최댓값. 길수록 PLC로 숨기기 어려움 |
| 검사별 건수 | 칸을 클릭하면 그 스트림·방향·검사로 목록이 걸러짐 |

손실이 있으면 빨간색으로 표시된다.

**원인 분석** (접힘): 펼치면 아래 두 차트가 나온다.
- **채널별 CRC 에러율**: 평균의 2배를 넘는 채널은 빨간색. 특정 채널만 높으면 간섭을 의심할 수 있다.
- **RSSI 히트맵**: X는 Event Counter, Y는 스트림+방향. 손실이 약전계 구간과 겹치는지 확인한다.

**이슈 목록**: 행마다 Item, Stream, Dir, Event, SE, 검사, 상세가 나온다. 최대 500건까지 표시.

---

### Tab 2: Packet Table

**파생 컬럼** (헤더가 파란색, CSV 컬럼 뒤에 추가됨)

| 컬럼 | 값 |
|---|---|
| Pair | C→P 행에만 표시: `OK` / `No Resp` |
| Ack | 상대 응답의 NESN 기준 `ACK` / `NACK` |
| Retx | 같은 이벤트 안 재전송 순번 `#1`, `#2` … |
| Payload State | `Data` / `Null` / `Empty` / `Len≠` / `Zero` |
| Issues | 그 패킷에 걸린 검사 이름 |

- 일반 컬럼과 똑같이 정렬, 필터, 검색, Export가 된다.
- 값이 하나도 없는 컬럼은 추가되지 않는다. 예: SN/NESN이 없으면 Ack 컬럼은 없음.

**이슈 이동**
- 필터 바의 `Issue [종류 ▾] ◀ ▶`, 또는 키보드 `n`(다음) / `p`(이전)
- 현재 필터·정렬 순서를 따르고, 처음과 끝에서는 반대쪽으로 넘어간다.
- 화면에는 2,000행씩 그려지며, 이동할 때 해당 행이 있는 구간으로 자동 전환된다.

**그 외**
- 컬럼 헤더 ▾: 엑셀 스타일 값 필터 (검색, Select All/None, Apply)
- 컬럼명 클릭: 정렬
- Errors only: CRC/Status 에러 행과 Gap 행만 표시
- Search: 전체 컬럼 텍스트 검색
- 같은 Event Counter끼리 배경 명암을 번갈아 주고, 이벤트 경계에 구분선을 긋는다.
- Event Counter를 건너뛴 곳에는 안내 줄 표시: `⚠ CIS 0x02 · P→C — Gap: 232 → 234 (1 missed)`

---

### Tab 3: Timeline

상단 버튼으로 모드를 전환한다.

#### ISO Event Grid (기본)

```
X축: Event Counter
행:  스트림별 SE1 C→P, SE1 P→C, SE2 C→P, …
```

칸 하나가 패킷 하나이고, 색은 Issues 탭 판정을 따른다. 범례에 종류별 건수가 표시된다.

| 표시 | 의미 |
|---|---|
| 초록 / 회색 | 정상 / Null PDU |
| 노랑 | 재전송 |
| 파랑 | Payload 이상 |
| 보라 | NACK인데 스니퍼 CRC는 OK (수신 측 문제 의심) |
| 주황 / 빨강 | CRC 에러 후 복구 / 손실 |
| 빨간 테두리 + X | C→P는 있는데 P→C 응답 없음 |
| 주황 점선 | Subevent 건너뜀 |
| 노란 박스 | 이벤트 전체가 없음 (EC Skip) |

#### RSSI / Channel

X는 Timestamp, Y는 RSSI 또는 채널 번호. 스트림+방향별 점과 선으로 그리고, 에러 패킷은 빨간 점이다.

#### Packet Pairing

같은 Event Counter에서 C→P와 P→C가 짝을 이루는지 이벤트 단위로 보여준다. 한쪽만 있으면 빨간 ✕를 표시한다.

#### 공통 조작

| 동작 | 기능 |
|---|---|
| 마우스 휠 | 줌 인/아웃 (마우스 위치 기준) |
| 드래그 | 좌우 패닝 |
| 마우스 올리기 | 패킷 상세 툴팁 (SN, NESN, NPI, CRC, 길이, 채널, RSSI, 관련 이슈) |
| Shift+드래그 → "Filter Selection → Table" | 선택한 Event Counter 구간으로 Packet Table 필터 |
| Reset Zoom | 줌/패닝 초기화 |

클릭해도 다른 탭으로 이동하지 않는다. 이동은 Shift+드래그 후 버튼을 누를 때만 일어난다.

---

## 검사 기준

같은 스트림·같은 이벤트의 패킷을 **캡처 순서대로** 보고 판단한다. CIS에서는 C→P 바로 다음 패킷을 그 응답으로 본다.

| 검사 | 필요 컬럼 | 판단 기준 |
|---|---|---|
| No Response | Direction, Event Counter | C→P 다음 패킷이 P→C가 아님 |
| NACK | + SN, NESN | 응답의 NESN이 보낸 패킷의 SN과 같음 (상대가 받지 못해 재전송 요청). P→C는 다음 C→P의 NESN으로 판단 |
| Corrupted · Recovered | CRC 또는 Status, Event Counter | 에러였지만 같은 이벤트 안에서 같은 SN이 ACK됨, 또는 깨진 패킷이 Null PDU |
| Corrupted · Lost | 위와 같음 | 이벤트가 끝날 때까지 전달이 확인되지 않음. 응답 없는 C→P 재전송은 전달로 보지 않음 |
| Empty Payload | Payload Length 또는 NPI | 이벤트의 첫 송신이 Null PDU. 대부분의 이벤트가 Null로 시작하는 방향(단방향 스트림 등)은 제외 |
| Length Mismatch | Payload Length | 그 스트림+방향의 대표 길이(최빈값)와 다름 |
| All-zero Payload | Payload | payload 바이트가 전부 0x00 |
| EC Skip | Event Counter | 스트림+방향별로 Event Counter가 불연속. 양방향이 같은 구간에서 빠지면 "캡처 누락 의심"으로 표시 |
| Subevent Skip | Event Counter, Subevent | 이벤트 안에서 양방향 모두 없는 Subevent 번호가 있음 (시작 번호는 캡처에서 자동 판단) |

**방향 판정**: 화살표 앞쪽, 즉 송신 측으로 판단한다.
- C→P: `Central→Peripheral`, `C->P`, `Master → Slave`, `M->S`, `Central`, `Master`
- P→C: `Peripheral→Central`, `P->C`, `Slave → Master`, `S->M`, `Peripheral`, `Slave`
- 판단할 수 없는 값(예: `Tx`)은 P→C로 처리되므로 Columns에서 직접 지정한다.

**에러 판정** (Corrupted 검사, Errors only 필터, CRC 셀 색에서 사용)
- 에러: `Fail`, `Error`, `Err`, `Bad`, `Invalid`, `Corrupt`, `Mismatch`, `NOK`, `NG`, `Miss`, `Timeout`, `Lost`, `Abort`를 포함하는 값
  - CRC 컬럼은 `0`, `false`, `no`도 에러로 본다.
- 정상: `OK`, `Pass`, `Good`, `Valid`, `Correct`, `Success`, `No error`, `None`
- Status 컬럼의 숫자 코드(예: `0`)는 에러로 보지 않는다. 필요하면 Columns에서 지정한다.

**손실 판정** (매트릭스의 전달률과 최대 연속 손실): 아래 중 하나에 해당하는 이벤트
- 이벤트 자체가 없음
- 해당 방향 패킷이 없음
- CRC Lost
- P가 끝까지 응답하지 않은 C→P SDU

---

## CSV 컬럼 자동 감지

컬럼명으로 자동 인식하므로 고정 포맷이 필요 없다. 컬럼 하나는 필드 하나에만 매칭된다.

| 분류 | 컬럼명 패턴 |
|---|---|
| 스트림 | CIS ID, BIS ID, CIG ID, BIG Handle |
| 시퀀스 | Event Counter, Subevent, SN, NESN, NPI |
| 시간 | Timestamp, Time |
| 방향 | Direction, Source, Flow |
| 물리 | PHY, Channel |
| 신호 | RSSI |
| 에러 | CRC, Status, Error |
| 페이로드 | Payload Length, Payload, Data |
| ISO 파라미터 | NSE, BN, FT, ISO Interval |

구분자(쉼표, 탭, 세미콜론)는 자동으로 감지한다. `.btt`는 Ellisys 전용 바이너리이므로 CSV로 Export해야 한다.

---

## Column Mapping

상단 **Columns** 버튼을 누르면 자동 감지 결과를 확인하고 고칠 수 있다.

- **필드별 CSV 컬럼**: 드롭다운으로 지정하고, 선택한 컬럼의 예시 값과 그 필드가 쓰이는 검사를 함께 보여준다.
- **Direction 값 → 송신 측**: 실제로 나온 Direction 값마다 C→P / P→C를 직접 고른다.
- **에러로 볼 값**: CRC/Status 컬럼에 실제로 나온 값마다 "에러" 여부를 체크한다.
- **적용**하면 모든 검사를 다시 계산한다. **자동 감지로 되돌리기**는 화면의 선택만 초기화하고, 적용을 눌러야 반영된다.
- 설정은 브라우저에 저장된다. **같은 컬럼 구성의 파일**을 다시 열면 자동으로 적용된다.
- CIS/BIS ID나 Event Counter를 찾지 못하면 파일을 열 때 이 화면이 자동으로 뜬다.

---

## 샘플 데이터

"Generate Sample Data"는 실제와 비슷한 CIS 캡처를 생성한다. 시드가 고정이라 매번 같은 데이터가 나온다.

- 설정: CIG 1개, CIS 2개, ISO Interval 10ms, NSE 3, FT 1, LE 2M, C→P 120B / P→C 40B
- SN/NESN이 ACK/재전송 규칙대로 움직이고, ACK된 쪽은 Null PDU를 보냄
- 일부러 넣은 이상
  - 채널 22 간섭
  - CIS 0x02 약전계 구간 (이벤트 100~149)
  - P 무응답 (0x01:57, 0x02:233)
  - EC 누락 (0x02의 200~202)
  - SE2 누락 (0x01:80, 0x02:260)
  - 전부 0인 payload (0x01:120), 길이 이상 (0x02:310), Null PDU (0x01:150~151)

---

## Export

"Export Report"는 현재 데이터를 CSV로 저장한다.
- 파생 컬럼(Pair, Ack, Retx, Payload State, Issues)이 포함된다.
- 에러 행에는 `[ERROR]`, Gap 행에는 `[GAP:N]` 표시가 추가된다.

---

## 알려진 제한

- **캡처 순서를 가정한다.** No Response와 NACK은 "바로 다음 패킷"으로 판단하므로, CSV가 시간순이 아니면 결과가 틀린다.
- **타임스탬프 단위**: `us`/`µs` 표기가 있으면 µs로, 그 외에는 ms로 가정한다.
- **BIS 전용 검사는 없다.** BN/IRC 반복 송신 누락은 검사하지 않는다. No Response와 NACK은 CIS 양방향 데이터에서만 동작한다.
- **Corrupted · Lost는 패킷 단위로 센다.** 한 SDU가 두 번 깨진 뒤 손실되면 2건이다.
- 실제 Ellisys CSV로는 아직 검증하지 않았다. 컬럼명이나 Direction·CRC 값 표기가 다르면 Columns에서 맞출 수 있지만, NPI 표기(`1` = Null PDU)가 다르면 코드 수정이 필요할 수 있다. Subevent 시작 번호(0 또는 1)는 자동으로 판단한다.

---

## 기술 스택

- 단일 HTML 파일 (외부 라이브러리 없음)
- HTML + CSS + Vanilla JavaScript, Canvas API로 차트와 타임라인 렌더링
- 브라우저 로컬에서만 동작
