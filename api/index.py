from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = b'\xc7<v\xad\xc9\x99\x1fl\xbaLx\x8c'  # 보안을 위해 변경 필요


def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


def is_valid_id(N):
    st = str(N)
    return len(st) == 5 and st.startswith('30') and 1 <= int(st[2]) <= 5 and 0 < int(st[3:]) <= 16


def get_betting_ratios(matches):
    updated_matches = []

    for match in matches:
        team1_bets = match['team1_bets']
        team2_bets = match['team2_bets']

        # 베팅 비율 계산 (0으로 나누는 경우 대비)
        if team1_bets == 0 and team2_bets == 0:
            ratio_text = "1:1"
            team1_ratio = 50
            team2_ratio = 50
        elif team1_bets == 0:
            ratio_text = "1:{:.2f}".format(team2_bets / 1)
            team1_ratio = 10  # 최소한의 너비 보장
            team2_ratio = 90
        elif team2_bets == 0:
            ratio_text = "{:.2f}:1".format(team1_bets / 1)
            team1_ratio = 90
            team2_ratio = 10
        else:
            ratio_text = "{:.2f}:{:.2f}".format(team1_bets / team2_bets, 1)
            total_bets = team1_bets + team2_bets
            team1_ratio = (team1_bets / total_bets) * 100
            team2_ratio = (team2_bets / total_bets) * 100

        updated_matches.append({
            **match,
            "ratio_text": ratio_text,
            "team1_ratio": team1_ratio,
            "team2_ratio": team2_ratio
        })

    return updated_matches

def init_db():
    with get_db_connection() as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER UNIQUE NOT NULL,
                password TEXT NOT NULL,
                tokens INTEGER DEFAULT 100,
                is_admin INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS bets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                match_id INTEGER NOT NULL,
                bet_amount INTEGER NOT NULL,
                chosen_team TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                team1 TEXT,
                team2 TEXT,
                team1_bets INTEGER DEFAULT 0,
                team2_bets INTEGER DEFAULT 0,
                result TEXT,
                bet_deadline DATETIME NOT NULL
            );
        ''')


@app.route('/')
def index():
    with get_db_connection() as conn:
        matches = conn.execute("SELECT id, team1, team2, team1_bets, team2_bets, result, bet_deadline FROM matches ORDER BY id").fetchall()

    rounds = []
    matches = get_betting_ratios(matches)
    match_list = list(matches)
    cur = 16  # 첫 라운드 경기 수

    while cur > 0 and match_list:
        round_matches = match_list[:cur]  # 현재 라운드 경기들
        rounds.append(round_matches)  # 리스트에 저장
        match_list = match_list[cur:]  # 다음 라운드 준비
        cur //= 2  # 경기 수 감소
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html', rounds=rounds)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        student_id = request.form['student_id']
        print(student_id)
        if not is_valid_id(student_id):
            return '잘못된 학번입니다.'
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        with get_db_connection() as conn:
            try:
                conn.execute('INSERT INTO users (student_id, password) VALUES (?, ?)', (student_id, hashed_password))
                conn.commit()
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                return '이미 존재하는 학번입니다.'
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        student_id = request.form['student_id']
        password = request.form['password']
        with get_db_connection() as conn:
            user = conn.execute('SELECT * FROM users WHERE student_id = ?', (student_id,)).fetchone()
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['is_admin'] = user['is_admin']
                return redirect(url_for('dashboard'))
            else:
                return '잘못된 학번 또는 비밀번호입니다.'
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        matches = conn.execute('SELECT * FROM matches').fetchall()
        matches = get_betting_ratios(matches)
        user_bets = conn.execute('''
            SELECT bets.id AS bet_id, matches.team1, matches.team2, bets.bet_amount, bets.chosen_team, matches.result
            FROM bets
            JOIN matches ON bets.match_id = matches.id
            WHERE bets.user_id = ?
        ''', (session['user_id'],)).fetchall()

    return render_template('dashboard.html', user=user, matches=matches, user_bets=user_bets)


@app.route('/cancel_bet', methods=['POST'])
def cancel_bet():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    bet_id = request.form['bet_id']

    with get_db_connection() as conn:
        # 베팅 정보 가져오기
        bet = conn.execute('SELECT * FROM bets WHERE id = ?', (bet_id,)).fetchone()
        if not bet:
            return '베팅이 존재하지 않습니다.'

        match = conn.execute('SELECT * FROM matches WHERE id = ?', (bet['match_id'],)).fetchone()
        if match and match['result']:  # 이미 결과가 정해진 경우 취소 불가
            return '이미 종료된 경기는 베팅을 취소할 수 없습니다.'

        # 토큰 환불
        conn.execute('UPDATE users SET tokens = tokens + ? WHERE id = ?', (bet['bet_amount'], session['user_id']))

        # 경기의 베팅 금액 수정
        if bet['chosen_team'] == match['team1']:
            conn.execute('UPDATE matches SET team1_bets = team1_bets - ? WHERE id = ?', (bet['bet_amount'], bet['match_id']))
        else:
            conn.execute('UPDATE matches SET team2_bets = team2_bets - ? WHERE id = ?', (bet['bet_amount'], bet['match_id']))

        # 베팅 삭제
        conn.execute('DELETE FROM bets WHERE id = ?', (bet_id,))
        conn.commit()

    return redirect(url_for('dashboard'))



@app.route('/bet', methods=['POST'])
def bet():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    match_id = request.form['match_id']
    bet_amount = int(request.form['bet_amount'])
    chosen_team = request.form['chosen_team']

    with get_db_connection() as conn:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        match = conn.execute('SELECT * FROM matches WHERE id = ?', (match_id,)).fetchone()

        if bet_amount > user['tokens']:
            return '토큰이 부족합니다.'

        # 현재 시간이 베팅 마감 시간을 넘었는지 확인
        current_time = datetime.now()
        bet_deadline = datetime.strptime(match['bet_deadline'], '%Y-%m-%d %H:%M:%S')

        if current_time > bet_deadline:
            return '베팅 마감 시간이 지났습니다.'

        conn.execute('INSERT INTO bets (user_id, match_id, bet_amount, chosen_team) VALUES (?, ?, ?, ?)',
                     (session['user_id'], match_id, bet_amount, chosen_team))
        conn.execute('UPDATE users SET tokens = tokens - ? WHERE id = ?', (bet_amount, session['user_id']))
        if chosen_team == match['team1']:
            conn.execute('UPDATE matches SET team1_bets = team1_bets + ? WHERE id = ?', (bet_amount, match_id))
        else:
            conn.execute('UPDATE matches SET team2_bets = team2_bets + ? WHERE id = ?', (bet_amount, match_id))
        conn.commit()
    return redirect(url_for('dashboard'))


@app.route('/admin', methods=['GET'])
def admin():
    if 'user_id' not in session or session.get('is_admin') != 1:
        return redirect(url_for('login'))
    with get_db_connection() as conn:
        matches = conn.execute('SELECT * FROM matches').fetchall()
    return render_template('admin.html', matches=matches)

@app.route('/admin/add_match', methods=['POST'])
def add_match():
    if 'user_id' not in session or session.get('is_admin') != 1:
        return redirect(url_for('login'))
    team1 = request.form['team1']
    team2 = request.form['team2']
    bet_deadline = request.form['bet_deadline']
    with get_db_connection() as conn:
        conn.execute('INSERT INTO matches (team1, team2, bet_deadline) VALUES (?, ?, ?)', (team1, team2, bet_deadline))
        conn.commit()
    return redirect(url_for('admin'))

@app.route('/admin/edit_match', methods=['POST'])
def edit_match():
    if 'user_id' not in session or session.get('is_admin') != 1:
        return redirect(url_for('login'))
    match_id = request.form['match_id']
    team1 = request.form['team1']
    team2 = request.form['team2']
    bet_deadline = request.form['bet_deadline']
    with get_db_connection() as conn:
        conn.execute('UPDATE matches SET team1 = ?, team2 = ?, bet_deadline = ? WHERE id = ?', (team1, team2, bet_deadline, match_id))
        conn.commit()
    return redirect(url_for('admin'))

@app.route('/admin/delete_match', methods=['POST'])
def delete_match():
    if 'user_id' not in session or session.get('is_admin') != 1:
        return redirect(url_for('login'))
    match_id = request.form['match_id']
    with get_db_connection() as conn:
        conn.execute('DELETE FROM matches WHERE id = ?', (match_id,))
        conn.commit()
    return redirect(url_for('admin'))

@app.route('/admin/close_betting', methods=['POST'])
def close_betting():
    if 'user_id' not in session or session.get('is_admin') != 1:
        return redirect(url_for('login'))
    match_id = request.form['match_id']
    with get_db_connection() as conn:
        conn.execute("UPDATE matches SET bet_deadline = datetime('now', 'LOCALTIME') WHERE id = ?", (match_id,))
        conn.commit()
    return redirect(url_for('admin'))


@app.route('/admin/set_result', methods=['POST'])
def set_result():
    if 'user_id' not in session or session.get('is_admin') != 1:
        return redirect(url_for('login'))

    match_id = request.form['match_id']
    result = request.form['result']

    with get_db_connection() as conn:
        match = conn.execute('SELECT * FROM matches WHERE id = ?', (match_id,)).fetchone()
        if not match:
            return '경기를 찾을 수 없습니다.'

        conn.execute('UPDATE matches SET result = ? WHERE id = ?', (result, match_id))

        total_bets = match['team1_bets'] + match['team2_bets']
        if total_bets > 0:
            if result == match['team1']:
                winning_bets = match['team1_bets']
            else:
                winning_bets = match['team2_bets']

            if winning_bets > 0:
                payout_ratio = total_bets / winning_bets

                winners = conn.execute('SELECT user_id, bet_amount FROM bets WHERE match_id = ? AND chosen_team = ?',
                                       (match_id, result)).fetchall()
                for winner in winners:
                    payout = int(winner['bet_amount'] * payout_ratio)
                    conn.execute('UPDATE users SET tokens = tokens + ? WHERE id = ?', (payout, winner['user_id']))

        conn.commit()

    return redirect(url_for('admin'))


@app.route('/bracket')
def bracket():
    with get_db_connection() as conn:
        matches = conn.execute("SELECT id, team1, team2, team1_bets, team2_bets, result FROM matches ORDER BY id").fetchall()

    rounds = []
    match_list = list(matches)
    cur = 16  # 첫 라운드 경기 수

    while cur > 0 and match_list:
        round_matches = match_list[:cur]  # 현재 라운드 경기들
        rounds.append(round_matches)  # 리스트에 저장
        match_list = match_list[cur:]  # 다음 라운드 준비
        cur //= 2  # 경기 수 감소

    return render_template("bracket.html", rounds=rounds)



if __name__ == '__main__':
    init_db()
    app.run()
