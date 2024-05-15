## 프로젝트 개요

IDS 작동 과정을 이해하기 위해 소형 IDS를 구현합니다.

## 실행환경

1. linux
2. gcc c99 이상

## 실행법

1. git clone
2. conf 폴더 내의 rule.txt에서 큐의 크기와 탐지스레드 개수, 룰 개수 수정 (혹은 그대로 둠)
3. 프로젝트 폴더에서 커맨드 실행 후 make 입력
4. ./IDS.out 실행

## 구조

1. detectpacket 스레드 1개 당 1개의 원형큐를 갖는다
2. readpacket 스레드는 패킷을 읽으면 라운드로빈 방식으로 원형큐에 패킷을 enqueue 한다
3. detectpacket은 자신이 갖고 있는 원형큐에서 dequeue 하여 정책과 비교하고, 걸리는 패킷을 logqueue에 저장한다.
4. logpacket은 logqueue 최대 크기의 80%가 넘게 패킷이 쌓일 때, 혹은 10초에 한 번씩 logqueue를 비워주며 로그를 저장한다.
5. log파일은 sqlite3에 저장된다.
