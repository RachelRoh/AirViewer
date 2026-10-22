# Ellisys LE Audio Viewer

Ellisys Bluetooth Analyzer에서 내보낸 CSV로 CIS/BIS 링크를 점검하는 단일 HTML 도구.

air log에서 주로 보는 네 가지를 자동으로 찾아준다.

1. Central은 보냈는데 Peripheral이 응답하지 않은 경우
2. 패킷이 깨진 경우 (재전송으로 복구됐는지, 결국 손실됐는지)
3. Payload가 유의미한 데이터로 채워졌는지 (Null PDU, 길이 이상, 전부 0)
4. Event Counter 또는 Subevent를 건너뛴 경우
5. (beta) 이벤트 앵커나 Subevent 송신 시각이 예상 스케줄에서 벗어난 경우

손실 판정은 BN/FT를 반영한 payload 단위다. FT>1이면 다음 이벤트에서 재전송돼 전달된 payload는 손실로 세지 않는다.

## 사용법

1. `ellisys_viewer.html`을 브라우저에서 열기 (더블클릭)
2. Ellisys에서 .btt를 열고 Overview를 CSV로 Export
3. CSV 파일을 드래그&드롭하거나 Browse로 로드
4. 파일이 없으면 "Generate Sample Data"로 먼저 확인 가능

> 설치 불필요, 인터넷 불필요. 파일 하나로 동작하고 데이터는 외부로 전송되지 않음.

### Export 시 넣을 컬럼

검사는 CSV에 있는 컬럼에 따라 자동으로 켜지고 꺼진다. Overview에 아래 컬럼을 추가한 뒤 Export하면 모든 검사가 동작한다.

> CIS ID(또는 BIS ID), CIG ID(또는 BIG Handle), Direction, Event Counter, Subevent, SN, NESN, NPI, CRC/Status, Payload Length, Payload(hex), Channel, RSSI, Timestamp

BN, FT 컬럼은 없어도 된다. 상단 Issues 탭의 **ISO 파라미터**에서 입력할 수 있고, 둘 다 없으면 BN=1, FT=1로 본다 (이전과 같은 이벤트 단위 판정).

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

**ISO 파라미터** (접힘, 맨 위): 판정에 쓰는 값을 확인하고 고친다. **적용**을 눌러야 다시 계산된다 ("입력 비우기"는 칸만 비운다). BN/FT/NSE/간격은 캡처마다 다르므로 저장하지 않고, Timestamp 단위와 허용 오차만 컬럼 매핑과 함께 브라우저에 저장된다.

| 항목 | 쓰이는 곳 | 비우면 |
|---|---|---|
| C→P / P→C BN | 이벤트당 기대 payload 수 | CSV의 BN 컬럼, 없으면 1 |
| C→P / P→C FT | payload를 다시 보낼 수 있는 이벤트 수 (Flush 시점) | CSV의 FT 컬럼, 없으면 1 |
| NSE | BN>1일 때 payload별 Flush 시점 | 캡처에서 본 가장 큰 Subevent 번호 |
| ISO_Interval, Sub_Interval (ms) | 타이밍 검사의 예상 시각 | 타임스탬프에서 추정 (아래 표에 스트림별 추정값) |
| Timestamp 단위 | 타임스탬프 해석 | 값에 붙은 단위. 단위가 없으면 ms로 읽되, 그러면 ISO 간격이 5 ms~4 s를 벗어날 때 s/µs/ns 중 맞는 단위를 자동으로 고른다 |
| 허용 오차 (µs) | 타이밍 검사 기준 | 20 µs |

단위를 지정했는데도 추정 ISO 간격이 5 ms~4 s를 벗어나면 경고를 띄운다. BN은 1~15, FT는 1~255로 제한한다. BN/FT는 `LL_CIS_REQ`나 `LE CIS Established` 이벤트에서 확인할 수 있다.

**검사 카드**: 검사별 건수. 클릭하면 아래 목록이 그 검사로 걸러진다.

**매트릭스**: 행은 스트림×방향, 열은 아래 항목이다.

| 열 | 의미 |
|---|---|
| BN/FT | 판정에 쓴 값. 마우스를 올리면 출처 (입력 / CSV / 기본값) |
| 전달률 | 전달된 payload 비율 = (첫 전송 성공 + 재전송 후 성공 + 다음 이벤트에서 성공) / (전달 + 손실). BN>1이면 이벤트당 BN개를 센다. 마우스를 올리면 내역 표시 |
| FT 이월 | FT>1일 때만 표시. 다음 이벤트로 넘어가 전달된 payload 수 |
| 최대 연속 손실 | 연속으로 손실된 payload 수의 최댓값. 길수록 PLC로 숨기기 어려움 |
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
| Retx | 같은 payload의 재전송 순번 `#1`, `#2` …. 다음 이벤트로 넘어간 재전송은 `#1 (이월)` |
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
| 노랑 | 재전송 (같은 이벤트) |
| 청록 | FT 이월 재전송 (이전 이벤트에서 시작한 payload) |
| 분홍 테두리 | Timing (beta) 검사에 걸린 패킷 |
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

#### Timing β

X는 Event Counter, Y는 편차(µs). 스트림별 선은 앵커 간격이 `Δ이벤트 × ISO_Interval`에서 벗어난 정도이고, 녹색 띠가 허용 오차다. 빨간 점은 Anchor Timing, ▲는 Slot Timing에 걸린 패킷이다. 점에 마우스를 올리면 값이 나온다.

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
| Corrupted · Recovered | CRC 또는 Status, Event Counter | 에러였지만 그 payload가 Flush 전에 ACK됨 (FT>1이면 다음 이벤트 포함), 또는 깨진 패킷이 Null PDU |
| Corrupted · Lost | 위와 같음 | 그 payload의 Flush 시점(첫 송신 이벤트 + FT − 1)까지 전달이 확인되지 않음. 응답 없는 C→P 재전송은 전달로 보지 않음 |
| Empty Payload | Payload Length 또는 NPI | 이벤트의 첫 송신이 Null PDU. 대부분의 이벤트가 Null로 시작하는 방향(단방향 스트림 등)은 제외 |
| Length Mismatch | Payload Length | 그 스트림+방향의 대표 길이(최빈값)와 다름 |
| All-zero Payload | Payload | payload 바이트가 전부 0x00 |
| EC Skip | Event Counter | 스트림+방향별로 Event Counter가 불연속. 양방향이 같은 구간에서 빠지면 "캡처 누락 의심"으로 표시 |
| Subevent Skip | Event Counter, Subevent | 이벤트 안에서 양방향 모두 없는 Subevent 번호가 있음 (시작 번호는 캡처에서 자동 판단) |
| Anchor Timing (beta) | Timestamp, Event Counter | 이웃한 두 이벤트(8개 이내)의 앵커 간격이 `Δ이벤트 × ISO_Interval`과 허용 오차 이상 다름. 한 이벤트만 어긋나면 그 이벤트와 다음 이벤트 두 곳에 표시된다 |
| Slot Timing (beta) | Timestamp, Event Counter, Subevent | C→P가 `앵커 + (SE−1) × Sub_Interval`에서 허용 오차 이상 벗어남, 또는 P→C 응답이 앞 C→P로부터 떨어진 간격이 그 스트림의 평소 간격(같은 C→P 길이끼리 비교)과 허용 오차 이상 다름 |

**Payload 모델 (FT / BN)**

손실·복구 판정과 전달률은 payload 단위로 한다. 근거는 Core spec Vol 6 Part B의 CIS 재전송/Flush 규칙이다.
- 이벤트마다 방향별로 BN개의 payload가 생긴다. i번째(1..BN) payload의 Flush 시점은 이벤트 `생성 + FT − 1`의 `NSE − floor(NSE/BN) × (BN − i)`번째 Subevent 끝이다. 송신 측은 ACK를 받거나 Flush될 때까지 같은 SN으로 다시 보내고, Flush 시점에는 송신·수신 양쪽이 SN/NESN을 넘긴다.
- 그룹: 같은 방향의 데이터 패킷은 SN이 같고 그 payload의 Flush 시점 전이면 하나의 payload다.
- 슬롯: payload는 순서대로 보내지므로, 각 그룹은 Flush 시점이 지나지 않은 가장 오래된 생성 payload에 대응한다. 건너뛴 슬롯은 한 번도 송신되지 않은 것으로 보고 손실로 센다. 캡처에서 빠진 이벤트도 BN개를 만든 것으로 보고, Null PDU만 보낸 이벤트는 오디오가 없는 것으로 보고 세지 않는다.
- ACK: 송신 후 Flush 시점 전, 그리고 이 방향이 다음 패킷을 보내기 전에 상대 패킷의 NESN이 이 SN을 넘어갔으면 전달이다. Null PDU의 NESN도 쓴다. 다른 이벤트의 패킷으로 판단할 때는 스니퍼 CRC가 OK인 패킷만 쓴다.
- 송신 측이 Flush 시점 전에 다음 payload나 Null PDU로 넘어갔으면 ACK를 받은 것이므로 전달로 본다.
- 그래도 ACK 정보가 없으면 (SN/NESN 컬럼 없음, 또는 Flush 전에 상대 패킷이 없음) 응답을 받은 CRC OK 송신이 있으면 전달로 추정한다.
- SN은 payload마다 (ACK든 Flush든) 한 번씩 넘어가므로, SN 홀짝으로 그룹과 슬롯의 순서를 다시 맞춘다 (캡처에서 빠진 payload가 있을 때).
- FT 이월: 첫 송신보다 뒤 이벤트에서 전달된 payload. 생성된 이벤트에서 한 번도 못 보내고 다음 이벤트에서 처음 보내 바로 전달된 경우는 첫 전송으로 센다 (캡처 누락이 있어도 흔들리지 않는 기준).
- SN 컬럼이 없으면 이벤트를 넘어 payload를 이을 수 없으므로 BN=1, FT=1로 판정한다 (출처 칸에 표시).
- 캡처가 Flush 시점 전에 끝난 payload는 판정하지 않는다.

FT=1, BN=1이면 이전 버전과 같은 결과가 나온다.

**타이밍 기준값**
- 앵커: 이벤트에서 Subevent 번호가 가장 작은 C→P 송신 시각에서 `(SE−1) × Sub_Interval`을 뺀 값
- ISO_Interval, Sub_Interval: 패널에 입력한 값, 없으면 캡처의 중앙값 (ISO는 4이벤트 이내 앵커 간격, Sub는 같은 이벤트 C→P 간격)

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

구분자(쉼표, 탭, 세미콜론)는 자동으로 감지한다. Timestamp는 `12.345 ms`, `12345 µs`, `0.012345 s`, `12 345.000 µs`(자릿수 구분 공백), `0:00:00.012345` 형식을 읽는다. `.btt`는 Ellisys 전용 바이너리이므로 CSV로 Export해야 한다.

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

### Sample: FT/BN · Timing

헤더의 "Sample: FT/BN · Timing" 버튼. 두 link layer를 그대로 시뮬레이션한다 (payload는 ACK 또는 Flush까지 재전송, SN/NESN은 ACK나 Flush 시점에 양쪽에서 증가).

- 설정: CIG 1개, CIS 2개, ISO Interval 10ms, NSE 4, Sub_Interval 1.1ms, LE 2M. C→P BN=2 FT=2 (60B), P→C BN=1 FT=2 (40B)
- 일부러 넣은 이상
  - 0x01:60 C→P 전부 실패, 0x01:61 SE1 실패 → C payload가 61로 이월돼 전달
  - 0x02:90 Peripheral이 이벤트 전체를 놓침
  - 0x02:140~141 C→P 전부 실패 → 140의 payload 2개가 FT 후 손실
  - 0x01:170 P→C 전부 실패 → 다음 이벤트로 이월
  - 타이밍: 0x02:120 앵커 +80µs (그 이벤트만), 0x01은 300부터 앵커 +60µs, 0x01:200 SE2 C→P +50µs, 0x02:250 SE1 응답 +40µs
  - 캡처 누락: 0x01 이벤트 350~351, 0x02:330 SE2

---

## 테스트

```
npm i -D playwright && npx playwright install chromium
node tests/verify.js
```

- 기존 샘플(FT=1)의 결과가 payload 모델 도입 전과 같은지
- 시뮬레이터가 기록한 실제 결과(payload마다 전달/손실)와 판정이 모두 일치하는지 (BN 1~3, FT 1~3, NSE 4~5, CRC 4~30%, 스니퍼·수신 측 CRC 불일치, 캡처 누락 포함 13개 설정). `FUZZ=1 node tests/verify.js`는 240개 설정(BN 1~3, FT 1~3, NSE 4~6, CRC 10/30%, 시드 4개)을 더 돈다 (몇 분)
- 이상한 입력: SN 없음 + BN=2, BN 200000 입력, 동떨어진 Event Counter 한 줄, 단위 없는 초 단위 Timestamp, 다음 파일로 설정이 넘어가는지
- 타이밍 검사가 주입한 이상만 정확히 잡는지
- Timestamp 형식, CSV의 BN/FT 컬럼, SN/NESN 없음, Timestamp/Direction 없음

---

## Export

"Export Report"는 현재 데이터를 CSV로 저장한다.
- 파생 컬럼(Pair, Ack, Retx, Payload State, Issues)이 포함된다.
- 에러 행에는 `[ERROR]`, Gap 행에는 `[GAP:N]` 표시가 추가된다.

---

## 알려진 제한

- **캡처 순서를 가정한다.** No Response와 NACK은 "바로 다음 패킷"으로 판단하므로, CSV가 시간순이 아니면 결과가 틀린다.
- **타임스탬프 단위**: s/ms/µs/ns 표기를 읽고, 표기가 없으면 ms로 읽은 뒤 ISO 간격이 5 ms~4 s에 들어오도록 단위를 고른다 (Timing 검사). RSSI/Channel 타임라인의 X축은 이전처럼 `us`/`µs` 표기만 구분하고 그 외는 ms로 표시한다.
- **BIS 전용 검사는 없다.** BN/IRC 반복 송신 누락은 검사하지 않는다. No Response와 NACK은 CIS 양방향 데이터에서만 동작한다.
- **Corrupted · Lost는 패킷 단위로 센다.** 한 payload가 두 번 깨진 뒤 손실되면 2건이다. 전달률은 payload 단위다.
- **캡처 누락 구간에서는 전달률이 실제와 다를 수 있다.** 캡처에서 빠진 이벤트의 payload와 송신이 하나도 캡처되지 않은 payload는 손실로 센다. 캡처된 payload의 전달/손실 판정은 시뮬레이터 검증에서 맞았다.
- **NSE를 캡처에서 추정한다.** BN>1이면 payload별 Flush 시점이 NSE에 달려 있는데, 캡처에 NSE개의 Subevent를 다 쓴 이벤트가 없으면 NSE를 작게 잡는다. 이때는 패널에 NSE를 입력한다.
- **Flush 시점 공식은 Core spec 원문으로 다시 확인할 필요가 있다.** `NSE − floor(NSE/BN) × (BN − i)`는 spec을 인용한 자료(ARM 특허 US20200260322A1)에서 가져왔다. 시뮬레이터도 같은 공식을 쓰므로, 공식 자체가 틀렸다면 테스트로는 잡히지 않는다.
- **타이밍 검사는 beta다.** 타임스탬프가 패킷의 시작인지 끝인지, 해상도가 어떤지 실제 Ellisys CSV로 확인하지 않았다. 응답 간격은 같은 C→P 길이끼리 비교하므로 시작/끝 기준 차이는 상쇄되지만, 허용 오차는 캡처 해상도에 맞게 조정해야 할 수 있다.
- 실제 Ellisys CSV로는 아직 검증하지 않았다. 컬럼명이나 Direction·CRC 값 표기가 다르면 Columns에서 맞출 수 있지만, NPI 표기(`1` = Null PDU)가 다르면 코드 수정이 필요할 수 있다. Subevent 시작 번호(0 또는 1)는 자동으로 판단한다.

---

## 기술 스택

- 단일 HTML 파일 (외부 라이브러리 없음)
- HTML + CSS + Vanilla JavaScript, Canvas API로 차트와 타임라인 렌더링
- 브라우저 로컬에서만 동작
