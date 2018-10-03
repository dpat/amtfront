from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from datetime import datetime
import requests, json, flask, sys, os

app = Flask(__name__)
app.secret_key = 'testing this out'

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/home', methods=['get'])
def home():

    baseurl = str(app.config.get('baseurl'))

    if 'userid' in session:
        userid = str(session['userid'])
    else:
        return redirect(url_for('login'))

    admin = False
    if session['admin']:
        admin = True

    url = (baseurl + '/user/' + userid)
    headers = {'content-type': 'application/json', 'token':app.config.get('token')}
    response = requests.get(url, headers=headers)
    user = json.loads(response.text)

    url = (baseurl + '/exam')
    response = requests.get(url, headers=headers)
    exams = json.loads(response.text)

    url = (baseurl + '/certificate/user/' + userid)
    headers = {'content-type': 'application/json', 'token':app.config.get('token')}
    response = requests.get(url, headers=headers)
    certs = json.loads(response.text)

    certdict = {}
    for cert in certs:
        if cert['examid'] in certdict and cert['passed']:
            if cert['testdate'] > certdict[cert['examid']]['testdate']:
                certdict[cert['examid']] = cert
        elif cert['examid'] not in certdict and cert['passed']:
            certdict[cert['examid']] = cert


    return render_template('home.html', admin=admin, user=user, exams=exams, certs=certdict)


@app.errorhandler(Exception)
def global_error(error):
    exam = session.get('exam')
    return render_template('error.html', exam=str(exam), error=str(error)), 500

@app.errorhandler(500)
def ise(error):
    exam = session.get('exam')
    return render_template('error.html', exam=str(exam), error=str(error)), 500

@app.errorhandler(404)
def page_not_found(error):
    exam = session.get('exam')
    return render_template('error.html', exam=str(exam), error=str(error)), 404

@app.route('/exam/<exam_id>', methods=['post','get'])
def exam(exam_id):

    baseurl = str(app.config.get('baseurl'))

    if 'userid' in session:
        userid = str(session['userid'])
    else:
        return redirect(url_for('login'))

    url = (baseurl + '/certificate/' + userid + '/' + exam_id)
    headers = {'content-type': 'application/json', 'token':app.config.get('token')}

    if request.method == 'POST':
        payload = []

        exam = get_session_var('exam')

        for qid in exam:

            if qid not in request.form:
                answerid = int(-1)
            else:
                answerid = int(request.form[qid])

            payload.append({"questionid":qid, "answerid":answerid})


        r = requests.post(url, data=json.dumps(payload), headers=headers)
        cert = json.loads(r.text)
        if 'exam' in session:
            session.pop('exam', None)

        if cert['incorrect']:
            incorrect = cert.pop('incorrect')
        else:
            incorrect = []

        return render_template('exam_complete.html', cert=cert, incorrect=incorrect)

    else:
        url = (baseurl + '/exam/' + exam_id + '/take')
        headers = {'content-type': 'application/json', 'token':app.config.get('token')}
        response = requests.get(url, headers=headers)

        session['exam'] = minimize_exam_dict(response.text)

        return render_template('exam.html', exam=json.loads(response.text), user_id=userid)


def minimize_exam_dict(exam):
    as_json = json.loads(exam)
    minimal = []
    for question in as_json['questions']:
        questid = question['questionid']
        minimal.append(str(questid))

    return minimal


@app.route('/exam/<exam_id>/ula', methods=['get'])
def ula(exam_id):
    baseurl = str(app.config.get('baseurl'))

    if 'userid' in session:
        userid = str(session['userid'])
    else:
        return redirect(url_for('login'))

    url = (baseurl + '/exam/' + exam_id)
    headers = {'content-type': 'application/json', 'token':app.config.get('token')}
    response = requests.get(url, headers=headers)
    exam = json.loads(response.text)
    ula = exam['ula']

    return render_template('ula.html', ula=ula, exam_id=exam_id)

@app.route('/logout', methods=['get'])
def logout():
    if 'userid' in session:
        session.pop('userid', None)
    if 'exam' in session:
        session.pop('exam', None)

    return redirect(url_for('login'))

@app.route('/settings', methods=['post','get'])
def settings():
    baseurl = str(app.config.get('baseurl'))

    if 'userid' in session:
        userid = str(session['userid'])
    else:
        return redirect(url_for('login'))

    if request.method == 'POST':
        amt_name = request.form.get('amt_name')
        kingdom = request.form.get('kingdom')

        url = (baseurl + '/user/' + userid)
        headers = {'content-type': 'application/json', 'token':app.config.get('token')}
        payload = {'amt_name':amt_name, 'kingdom':kingdom}
        response = requests.put(url, data=json.dumps(payload), headers=headers)
        return redirect(url_for('settings'))

    else:
        url = (baseurl + '/user/' + userid)
        headers = {'content-type': 'application/json', 'token':app.config.get('token')}
        response = requests.get(url, headers=headers)
        user = json.loads(response.text)

        return render_template('settings.html', user=user)

@app.route('/admin')
def admin():

    baseurl = str(app.config.get('baseurl'))

    if 'userid' in session:
        userid = str(session['userid'])
    else:
        return redirect(url_for('login'))

    if not session["admin"]:
        return redirect(url_for('home'))

    url = (baseurl + '/exam')
    headers = {'content-type': 'application/json', 'token':app.config.get('token')}
    response = requests.get(url, headers=headers)
    exams = json.loads(response.text)

    return render_template('admin.html', exams=exams)

@app.route('/admin/users', methods=['get'])
def admin_user_view():

    baseurl = str(app.config.get('baseurl'))

    if 'userid' in session:
        userid = str(session['userid'])
    else:
        return redirect(url_for('login'))

    if not session["admin"]:
        return redirect(url_for('home'))

    url = (baseurl + '/user')
    headers = {'content-type': 'application/json', 'token':app.config.get('token')}
    response = requests.get(url, headers=headers)
    users = json.loads(response.text)

    return render_template('admin_user_select.html', users=users)

@app.route('/admin/user/<user_id>', methods=['post','get'])
def admin_user(user_id):

    baseurl = str(app.config.get('baseurl'))

    if 'userid' in session:
        userid = str(session['userid'])
    else:
        return redirect(url_for('login'))

    if not session["admin"]:
        return redirect(url_for('home'))

    url = (baseurl + '/user/' + user_id)
    headers = {'content-type': 'application/json', 'token':app.config.get('token')}
    response = requests.get(url, headers=headers)
    user = json.loads(response.text)

    if request.method=='POST':

        if request.form.get('delete') == 'delete':
            url = (baseurl + '/user/' + user_id)
            headers = {'content-type': 'application/json', 'token':app.config.get('token')}
            r = requests.delete(url, headers=headers)

        else:
            name = request.form.get('name')
            email = request.form.get('email')
            amt_name = request.form.get('amt_name')
            kingdom = request.form.get('kingdom')
            admin = request.form.get('admin')

            url = (baseurl + '/user/' + user_id)
            headers = {'content-type': 'application/json', 'token':app.config.get('token')}
            payload = {'name':name, 'email':email, 'amt_name':amt_name, 'kingdom':kingdom, 'admin':json.loads(admin)}
            r = requests.put(url, data=json.dumps(payload), headers=headers)

        return redirect(url_for('admin_user_view'))

    else:
        return render_template('admin_user.html', user=user)


@app.route('/admin/certs/<method>', methods=['get'])
def admin_certs(method):

    baseurl = str(app.config.get('baseurl'))

    if 'userid' in session:
        userid = str(session['userid'])
    else:
        return redirect(url_for('login'))

    if method == "all":
        url = (baseurl + '/certificate')
        headers = {'content-type': 'application/json', 'token':app.config.get('token')}
        response = requests.get(url, headers=headers)
        certs = json.loads(response.text)
        return render_template('admin_certs.html', certs=certs)


@app.route('/admin/exam/<exam_id>', methods=['post','get'])
def admin_exam(exam_id):

    baseurl = str(app.config.get('baseurl'))

    if 'userid' in session:
        userid = str(session['userid'])
    else:
        return redirect(url_for('login'))

    if not session["admin"]:
        return redirect(url_for('home'))

    url = (baseurl + '/exam')
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

        elif request.form.get('delete') == 'delete':
            url = (baseurl + '/exam/' + exam_id)
            r = requests.delete(url, headers=headers)

        else:
            name = request.form.get('name')
            pass_percent = request.form.get('pass_percent')
            time_limit = request.form.get('time_limit')
            expiration = request.form.get('expiration')
            ula = request.form.get('ula')

            url = (baseurl + '/exam/' + exam_id)
            payload = {'name':name, 'pass_percent':int(pass_percent), 'time_limit':int(time_limit), 'expiration':int(expiration), 'ula':ula}
            r = requests.put(url, data=json.dumps(payload), headers=headers)

        return redirect(url_for('admin'))

    else:
        if exam_id == 'new':
            sections = []
            exam = {}
            return render_template('admin_exam.html', sections=sections, exam_id=exam_id, exam=exam)

        else:
            url = (baseurl + '/exam/' + exam_id + '/section')
            headers = {'content-type': 'application/json', 'token':app.config.get('token')}
            response = requests.get(url, headers=headers)
            sections = json.loads(response.text)
            url = (baseurl + '/exam/' + exam_id)
            response = requests.get(url, headers=headers)
            exam = json.loads(response.text)

            return render_template('admin_exam.html', sections=sections, exam_id=exam_id, exam=exam)

@app.route('/admin/section/<exam_id>/<section_id>', methods=['post','get'])
def admin_section(exam_id, section_id):

    baseurl = str(app.config.get('baseurl'))

    if 'userid' in session:
        userid = str(session['userid'])
    else:
        return redirect(url_for('login'))

    if not session["admin"]:
        return redirect(url_for('home'))

    headers = {'content-type': 'application/json', 'token':app.config.get('token')}

    if request.method == 'POST':
        if section_id == 'new':
            #post new test
            name = request.form.get('name')
            active_questions = request.form.get('active_questions')

            url = (baseurl + '/exam/' + exam_id + '/section')
            headers = {'content-type': 'application/json', 'token':app.config.get('token')}
            payload = {'name':name, 'exam_id':int(exam_id), 'active_questions':int(active_questions)}
            r = requests.post(url, data=json.dumps(payload), headers=headers)

        elif request.form.get('delete') == 'delete':
            url = (baseurl + '/section/' + section_id)
            r = requests.delete(url, headers=headers)
        else:
            name = request.form.get('name')
            active_questions = request.form.get('active_questions')

            url = (baseurl + '/section/' + section_id)
            headers = {'content-type': 'application/json', 'token':app.config.get('token')}
            payload = {'name':name, 'exam_id':int(exam_id), 'active_questions':int(active_questions)}
            r = requests.put(url, data=json.dumps(payload), headers=headers)

        return redirect(url_for('admin_exam', exam_id=exam_id))

    else:

        if section_id=='new':
            section = {}
        else:
            url = (baseurl + '/section/' + section_id)
            headers = {'content-type': 'application/json', 'token':app.config.get('token')}
            response = requests.get(url, headers=headers)
            section = json.loads(response.text)

        return render_template('admin_section.html', exam_id=exam_id, section_id=section_id, section=section)

@app.route('/admin/question/<exam_id>/<section_id>/<question_id>', methods=['post','get'])
def admin_question(exam_id, section_id, question_id):

    baseurl = str(app.config.get('baseurl'))

    if 'userid' in session:
        userid = str(session['userid'])
    else:
        return redirect(url_for('login'))

    if not session["admin"]:
        return redirect(url_for('home'))

    headers = {'content-type': 'application/json', 'token':app.config.get('token')}

    if request.method == 'POST':
        if question_id == 'new':

            question = request.form.get('question')

            url = (baseurl + '/section/' + section_id + '/question')
            headers = {'content-type': 'application/json', 'token':app.config.get('token')}
            payload = {'question':question, 'section_id':int(section_id)}
            r = requests.post(url, data=json.dumps(payload), headers=headers)
            response = json.loads(r.text)
            question_id = response['questionid']

            for i in range(1, 5):
                answer = request.form.get('answer' + str(i))
                correct = request.form.get('correct' + str(i))
                if answer and correct:
                    url = (baseurl + '/question/' + str(question_id) + '/answer')
                    headers = {'content-type': 'application/json', 'token':app.config.get('token')}
                    payload = {'answer':answer, 'question_id':int(question_id), 'correct':json.loads(correct)}
                    r = requests.post(url, data=json.dumps(payload), headers=headers)


        elif request.form.get('delete') == 'delete':

            url = (baseurl + '/question/' + question_id)
            r = requests.delete(url, headers=headers)

        else:
            question = request.form.get('question')

            url = (baseurl + '/question/' + question_id)
            headers = {'content-type': 'application/json', 'token':app.config.get('token')}
            payload = {'question':question, 'section_id':int(section_id)}
            r = requests.put(url, data=json.dumps(payload), headers=headers)
            r = requests.get(url, headers=headers)
            response = json.loads(r.text)
            answers = response['answers']

            for answer in answers:
                ans = request.form.get('answer' + str(answer["answerid"]))
                correct = request.form.get('correct' + str(answer["answerid"]))

                if ans and correct:
                    url = (baseurl + '/answer/' + str(answer['answerid']))
                    headers = {'content-type': 'application/json', 'token':app.config.get('token')}
                    payload = {'answer':ans, 'question_id':int(question_id), 'correct':json.loads(correct)}
                    r = requests.put(url, data=json.dumps(payload), headers=headers)

        return redirect(url_for('admin_section', exam_id=exam_id, section_id=section_id))

    else:

        if question_id=='new':
            question = {}
        else:
            url = (baseurl + '/question/' + question_id)
            headers = {'content-type': 'application/json', 'token':app.config.get('token')}
            response = requests.get(url, headers=headers)
            question = json.loads(response.text)

        return render_template('admin_question.html', exam_id=exam_id, section_id=section_id, question_id=question_id, question=question)

@app.route('/admin/answer/<exam_id>/<section_id>/<question_id>/<answer_id>', methods=['post','get'])
def admin_answer(exam_id, section_id, question_id, answer_id):

    baseurl = str(app.config.get('baseurl'))

    if 'userid' in session:
        userid = str(session['userid'])
    else:
        return redirect(url_for('login'))

    if not session["admin"]:
        return redirect(url_for('home'))

    headers = {'content-type': 'application/json', 'token':app.config.get('token')}

    if request.method == 'POST':
        if answer_id == 'new':

            answer = request.form.get('answer')
            correct = request.form.get('correct')


            url = (baseurl + '/question/' + question_id + '/answer')
            headers = {'content-type': 'application/json', 'token':app.config.get('token')}
            payload = {'answer':answer, 'question_id':int(question_id), 'correct':json.loads(correct)}
            r = requests.post(url, data=json.dumps(payload), headers=headers)
            return redirect(url_for('admin_question', exam_id=exam_id, section_id=section_id, question_id=question_id))

        elif request.form.get('delete') == 'delete':
            url = (baseurl + '/answer/' + answer_id)
            r = requests.delete(url, headers=headers)

        else:

            answer = request.form.get('answer')
            correct = request.form.get('correct')

            url = (baseurl + '/answer/' + answer_id)
            headers = {'content-type': 'application/json', 'token':app.config.get('token')}
            payload = {'answer':answer, 'question_id':int(question_id), 'correct':json.loads(correct)}
            r = requests.put(url, data=json.dumps(payload), headers=headers)
            return redirect(url_for('admin_question', exam_id=exam_id, section_id=section_id, question_id=question_id))


        return redirect(url_for('admin_question', exam_id=exam_id, section_id=section_id, question_id=question_id))

    else:

        if answer_id == "new":
            answer = {}
        else:
            url = (baseurl + '/answer/' + answer_id)
            headers = {'content-type': 'application/json', 'token':app.config.get('token')}
            response = requests.get(url, headers=headers)
            answer = json.loads(response.text)

        return render_template('admin_answer.html', answer=answer)



@app.route('/handle_data', methods=['POST'])
def handle_data():

    baseurl = str(app.config.get('baseurl'))

    if request.method == 'POST':

        payload = request.get_json()
        url = (baseurl + '/user')
        headers = {'content-type': 'application/json', 'token':app.config.get('token')}
        r = requests.post(url, data=json.dumps(payload), headers=headers)
        response = json.loads(r.text)


        session['userid'] = response["userid"]
        session['admin'] = response["admin"]
        return json.dumps(response)


def get_session_var(variable):
    var = session.get(variable)
    if not var:
        message = 'Failed to find session variable %s' % var
        return render_template('error.html', exam=None,
                               error=message), 500
    return var


if __name__=='__main__':
    import argparse
    from OpenSSL import SSL
    parser = argparse.ArgumentParser()
    parser.add_argument('baseurl')
    parser.add_argument('token')
    args = parser.parse_args()
    app.config['baseurl'] = args.baseurl
    app.config['token'] = args.token

    app.run(port=8000, ssl_context='adhoc')
