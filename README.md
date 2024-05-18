## 프로젝트 개요

소형 IDS를 구현합니다. 해당 프로그램은 아래의 조건을 만족해야 합니다.

* conf 폴더 내의 사용자가 작성한 config 파일을 읽어와 프로그램의 초기 설정을 구축해야 합니다.

  - 파일에서 정의하는 내용: 큐 사이즈, 스레드 개수, 정책 개수, ICMP FLOOD 탐지 여부

* 사용자가 만약 ICMP FLOOD 탐지를 희망한다면, conf 폴더 내의 사용자가 작성한 flood_conf 파일을 읽어와 ICMP FLOOD 탐지 초기 설정을 구축해야 합니다.
  - 파일에서 정의하는 내용: 해시테이블 크기, 공격 인정 시간, 공격 인정 패킷 수

* conf 폴더 내의 사용자가 작성한 rule.txt 파일을 읽어와 IDS가 탐지할 정책을 구축해야 합니다.
  - 파일에서 정의하는 내용: 패턴 블럭을 반드시 포함하고 있는 정책. ip 주소와 포트번호는 선택

* 멀티 스레드로 구현되어야 합니다.

<br> 

## 실행환경

1. linux 
2. gcc c99 이상

<br>

### 실행법

1. 원하는 폴더에서 `git clone https://github.com/Hayeon-Lee/IDS.git` 를 입력합니다.
2. conf 폴더 내의 config, flood_conf, rule.txt 를 수정하거나 혹은 그대로 둡니다. 
3. 프로젝트 폴더로 이동 후 `make` 를 입력합니다.
4. `./IDS.out` 를 입력합니다.
5. 프로그램을 종료하고 싶을 때는 ctrl + c 를 입력합니다.

<br>

## 구조도
<img src="Structure_Diagram.png" />

<br>

## 프로그램 설명

### 사용자 정의 파일 설명

#### conf/config
1. 큐 사이즈는 이 프로그램에서 사용되는 Packet Queue, Danger Packet Queue, Log Queue 의 사이즈입니다.
2. 스레드 개수는 detect packet thread 의 개수입니다. detect packet thread는 패킷을 파싱하고, 정책과 비교하는 등 타 스레드에 비해 할 일이 많아 여러 개로 만들었습니다. Packet Queue는 detect packet thread 당 한 개씩 갖기 때문에, 스레드 개수가 곧 Packet Queue의 개수입니다.
3. 정책 개수는 rule.txt 파일에 작성된 정책의 총 개수입니다. 프로그램은 rule.txt 파일에서 이 파일에 적힌 정책 개수만큼만 정책을 읽어옵니다.
4. ICMP FLOOD 탐지 여부는 ICMP FlOOD 공격과 Smurf 공격을 탐지할 지에 대한 여부를 결정합니다.

#### conf/flood_config  
1. 해시테이블 크기는 ip 주소로 해시테이블을 만들 때 필요한 테이블의 크기입니다. ip주소를 해싱한 뒤 이 크기로 나누어 인덱스를 부여합니다.
2. 공격 인정 시간과 공격 인정 패킷 수는 icmp echo ping flood를 탐지할 때 사용됩니다. 만약 특정 ip 주소로부터 공격 인정 시간동안 공격 인정 패킷 수 이상의 패킷이 유입됐을 경우 이를 icmp flood로 분류합니다.

#### conf/rule.txt
1. 탐지하고 싶은 패킷의 특징을 정의합니다. pattern 은 반드시 포함해야 합니다. (pattern이란, 패킷의 헤더를 제외한 데이터 부분에 있는 내용을 말합니다.)
2. 정의할 수 있는 기타 특징에는 src ip, dst ip, src port, dst port, src mac, dst mac 이 있습니다.
3. 모든 패턴은 | (파이프) 특수 기호를 가져야하고, 파이프 기호는 정책의 이름과 내용을 구분짓습니다.
4. 정책의 내용 내부의 각 특징은 ; (세미콜론) 으로 구분되어야 합니다.

### 기능 설명

#### Main

#### Read Packet 

#### Detect Packet

#### Log Packet
