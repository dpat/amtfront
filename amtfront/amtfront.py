from flask import Flask, render_template, request, jsonify, redirect, url_for
from OpenSSL import SSL
import requests, json, flask, sys, ast, click

app = Flask(__name__)

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/home/<userid>', methods=['get'])
def home(userid):
    url = ('http://localhost:5000/amttest/api/user/' + userid)
    headers = {'content-type': 'application/json', 'token':app.config.get('token')}
    response = requests.get(url, headers=headers)
    user = json.loads(response.text)

    url = ('http://localhost:5000/amttest/api/exam')
    response = requests.get(url, headers=headers)
    exams = json.loads(response.text)

    url = ('http://localhost:5000/amttest/api/certificate/user/' + userid)
    headers = {'content-type': 'application/json', 'token':app.config.get('token')}
    response = requests.get(url, headers=headers)
    certs = json.loads(response.text)


    return render_template('home.html', user=user, exams=exams, certs=certs)

@app.route('/exam/<exam_id>', methods=['post','get'])
def exam(exam_id):

    user_id = request.args.get('user_id')

    url = ('http://localhost:5000/amttest/api/certificate/' + user_id + '/' + exam_id)
    headers = {'content-type': 'application/json', 'token':app.config.get('token')}

    if request.method == 'POST':
        payload = []
        exam = request.form.get('exam')
        exam = ast.literal_eval(exam)
        print(exam, file=sys.stderr)

        for question in exam["questions"]:
            #post new test
            quid = str(question['questionid'])
            answerid = request.form[quid]
            payload.append({"questionid":question['questionid'], "answerid":answerid})

        print(payload, file=sys.stderr)
        r = requests.post(url, data=json.dumps(payload), headers=headers)
        return redirect(url_for('home'))

    else:
        url = ('http://localhost:5000/amttest/api/exam/' + exam_id + '/take')
        headers = {'content-type': 'application/json', 'token':app.config.get('token')}
        response = requests.get(url, headers=headers)
        exam = json.loads(response.text)

        return render_template('exam.html', exam=exam, user_id=user_id)

@app.route('/admin')
def admin():
    url = ('http://localhost:5000/amttest/api/exam')
    headers = {'content-type': 'application/json', 'token':app.config.get('token')}
    response = requests.get(url, headers=headers)
    exams = json.loads(response.text)

    return render_template('admin.html', exams=exams)

@app.route('/admin/exam/<exam_id>', methods=['post','get'])
def admin_exam(exam_id):

    print(app.config.get('token'), file=sys.stderr)
    url = ('http://localhost:5000/amttest/api/exam')
    headers = {'content-type': 'application/json', 'token':app.config.get('token')}

    if request.method == 'POST':
        if exam_id == 'new':
            #post new test
            name = request.form.get('name')
            pass_percent = request.form.get('pass_percent')
            time_limit = request.form.get('time_limit')
            expiration = request.form.get('expiration')
            ula = request.form.get('ula')

            payload = {'name':name, 'pass_percent':int(pass_percent), 'time_limit':int(time_limit), 'expiration':int(expiration), 'ula':ula}
            r = requests.post(url, data=json.dumps(payload), headers=headers)
            return redirect(url_for('admin'))

    else:
        if exam_id == 'new':
            sections = []
        else:
            url = ('http://localhost:5000/amttest/api/exam/' + exam_id + '/section')
            headers = {'content-type': 'application/json', 'token':app.config.get('token')}
            response = requests.get(url, headers=headers)
            sections = json.loads(response.text)

        return render_template('admin_exam.html', sections=sections)

@app.route('/admin/section/<section_id>', methods=['post','get'])
def admin_section(section_id):

    if request.method == 'POST':
        if section_id == 'new':
            #post new test
            name = request.form.get('name')
            exam_id = request.form.get('exam_id')
            active_questions = request.form.get('active_questions')
            archive = request.form.get('archive')

            url = ('http://localhost:5000/amttest/api/exam/' + exam_id + '/section')
            headers = {'content-type': 'application/json', 'token':app.config.get('token')}
            payload = {'name':name, 'exam_id':int(exam_id), 'active_questions':int(active_questions), 'archive':bool(archive)}
            r = requests.post(url, data=json.dumps(payload), headers=headers)
            return redirect(url_for('admin_exam', exam_id=exam_id))


    else:

        url = ('http://localhost:5000/amttest/api/section/' + section_id)
        headers = {'content-type': 'application/json', 'token':app.config.get('token')}
        response = requests.get(url, headers=headers)
        section = json.loads(response.text)

        return render_template('admin_section.html', section=section)

@app.route('/admin/question/<question_id>', methods=['post','get'])
def admin_question(question_id):

    if request.method == 'POST':
        if question_id == 'new':
            #post new test
            question = request.form.get('question')
            section_id = request.form.get('section_id')

            url = ('http://localhost:5000/amttest/api/section/' + section_id + '/question')
            headers = {'content-type': 'application/json', 'token':app.config.get('token')}
            payload = {'question':question, 'section_id':int(section_id)}
            r = requests.post(url, data=json.dumps(payload), headers=headers)
            return redirect(url_for('admin_section', section_id=section_id))


    else:
        url = ('http://localhost:5000/amttest/api/question/' + question_id)
        headers = {'content-type': 'application/json', 'token':app.config.get('token')}
        response = requests.get(url, headers=headers)
        question = json.loads(response.text)

        return render_template('admin_question.html', question=question)

@app.route('/admin/answer/<answer_id>', methods=['post','get'])
def admin_answer(answer_id):

    if request.method == 'POST':
        if answer_id == 'new':
            #post new test
            answer = request.form.get('answer')
            question_id = request.form.get('question_id')
            correct = request.form.get('correct')


            url = ('http://localhost:5000/amttest/api/question/' + question_id + '/answer')
            headers = {'content-type': 'application/json', 'token':app.config.get('token')}
            payload = {'answer':answer, 'question_id':int(question_id), 'correct':bool(correct)}
            r = requests.post(url, data=json.dumps(payload), headers=headers)
            return redirect(url_for('admin_question', question_id=question_id))

    else:
        url = ('http://localhost:5000/amttest/api/answer/' + answer_id)
        headers = {'content-type': 'application/json', 'token':app.config.get('token')}
        response = requests.get(url, headers=headers)
        answer = json.loads(response.text)

        return render_template('admin_answer.html', answer=answer)



@app.route('/handle_data', methods=['POST'])
def handle_data():

    if request.method == 'POST':
        payload = request.get_json()
        print(payload, file=sys.stderr)
        userid = payload["fbuserid"]

        url = ('http://localhost:5000/amttest/api/user')
        headers = {'content-type': 'application/json', 'token':app.config.get('token')}
        r = requests.post(url, data=json.dumps(payload), headers=headers)
        response = json.loads(r.text)
        return json.dumps(response)

if __name__=='__main__':
    app.config['token'] = sys.argv[1]
    app.run(port=8000, ssl_context='adhoc')
