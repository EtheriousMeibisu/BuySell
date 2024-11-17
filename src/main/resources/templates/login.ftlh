<#import "blocks/template.ftlh" as t>
<@t.template user>
    <h1 style="text-align: center">Авторизация</h1>
    <hr>
    <form action="/login " method="post">
        <div class="mb-3">
            <label for="email" class="form-label">Электронная почта</label>
            <input type="email" class="form-control" placeholder="name@example.com" id="email" name="username">
            <div id="email" class="invalid-tooltip">
                Неверная электронная почта
            </div>
        </div>
        <div class="form-group">
            <label for="password">Пароль</label>
            <input type="password" class="form-control" id="password" name="password">
            <div id="password" class="invalid-feedback">
                Неверный пароль
            </div>
        </div>
        <input type="hidden" name="_csrf" value="${_csrf.token}">
        <button type="submit" style="width: 100%" class="btn btn-dark">Войти</button>
    </form>
    <hr>
    <h2>Нет аккаунта BUYSELL? <a href="/registration">Зарегистрируйся!</a></h2>
</@t.template>