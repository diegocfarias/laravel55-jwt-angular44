# Laravel 5.5 + JWT + Angular 4.4
---
Baseado na série de vídeos da TJG Web
Link para o curso: [https://youtu.be/qA5bwYfmAqE](https://youtu.be/qA5bwYfmAqE)
Repositório do curso: [https://github.com/tjgweb/curso-laravel-jwt-angular](https://github.com/tjgweb/curso-laravel-jwt-angular)
---

### Instalando o Laravel
```
composer create-project --prefer-dist laravel/laravel project-name
```
### Criando a base de dados (MySQL)
1. Criar o banco de dados;
2. Configurar os dados de acesso do banco de dados no arquivo *.env*;
```
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=nome_do_bd
DB_USERNAME=username
DB_PASSWORD=password
```
__OBS.:__ *Ao instalar o Laravel ele já cria por padrão uma migration __Users__ e uma __Password Resets__.*

3. Criar um __Seeds__ para quando criar nossa tabela através do artsan migrate já inserir um usuário nessa tabela.
```
php artisan make:seeder UsersTableSeeder
```
*O Laravel já cria uma __Model__ para User e uma __Factory__, o Seeder vai criar um usuário baseado na model, se a senha __não__ for informada no Seeder ela é definida como “secret” por padrão na Factory (database/factories).*
```
<?php

use Illuminate\Database\Seeder;

class UsersTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        factory(App\User::class)->create([
            'name' => 'Anderson Moraes',
            'email' => 'anderson.b4w@gmail.com'
        ]);
    }
}
```

4. No DatabaseSeeder, descomentar a linha abaixo para que o seeder criado seja chamado ao executarmos o artsan migate.
```
$this->call(UsersTableSeeder::class);
```
5. Criar as tabelas através do __migrate__.
```
php artisan migrate --seed
```
*É necessário __--seed__ para que a tabela seja criada já com os dados de usuário informado no seed criado.*

### Instalando a biblioteca JWT
*A biblioteca JWT será responsável por gerar o token e verificar sua validade.*
Link para biblioteca [https://github.com/tymondesigns/jwt-auth/tree/0.5.12](https://github.com/tymondesigns/jwt-auth/tree/0.5.12).
*Essa biblioteca ainda não tá finalizada, a versão 1.0.0 está preste a sair, por enquanto usaremos a versão estável, que é a 0.5.12.*
1. Clica na documentação (Wiki) e em install, vamos instalar via composer.
```
composer require tymon/jwt-auth:0.5.12
```
2. No arquivo __composer.json__ em __require__ verifique se a linha abaixo foi inserida, caso contrario insira.
```
"tymon/jwt-auth": "0.5.12"
```
3. Registrar o service provider em providers.
 3.1. Abrir o arquivo __config/app.php__ e rola até providers, em __peckage service providers__ colar a linha abaixo:
```
/*
* Package Service Providers...
*/
Tymon\JWTAuth\Providers\JWTAuthServiceProvider::class,
```
4. Registrar os Alias.
 4.1. Ainda no arquivo app.php adicionar os alias:
```
'JWTAuth' => Tymon\JWTAuth\Facades\JWTAuth::class,
'JWTFactory' => Tymon\JWTAuth\Facades\JWTFactory::class
```
5. Rodar um comando no Laravel para gerar um arquivo de configuração do JWT, esse arquivo será gerado dentro da pasta config.
```
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\JWTAuthServiceProvider"
```
6. Abrir o arquivo jwt.php gerado na pasta config e configurá-lo:
 6.1. Alterar o __JWT_SECRET__, é ele que garante a integridade das informações, ele pode ser alterado direto __changeme__ ou no arquivo __.env__, que é o mais recomendado.
```
'secret' => env('JWT_SECRET', 'changeme'),
```
No arquivo __.env__ inserir a chave:
```
JWT_SECRET=U2R7kGM=
```
__OBS.:__ *A chave pode ser gerada com o comando php __artisan jwt:generate__, é recomendado pegar os últimos 8 dígitos do __APP_KEY__ gerado na instalação do Laravel, que é único. pode ser inserido mais de 8 dígitos, mas quanto maior a chave, maior o tamanho do token, que gera mais tráfico.*
7. Configurar o __tempo de validade__ do token, que por padrão é de 60 minutos:
```
 'ttl' => 60
```
8. Configurar o __tempo de refresh__ do token, que por padrão é de duas semanas:
```
refresh_ttl' => 20160
```
9. Abrir a documentação do [tumon/jtw-auth](https://github.com/tymondesigns/jwt-auth/wiki/Authentication), em Authentication e copiar dois Middlewares de proteção de rotas, em seguida abrir o arquivo __kernel.php__ em __app/http__ e colar os middlewares copiados.
```
protected $routeMiddleware = [
    ...
  'jwt.auth' => \Tymon\JWTAuth\Middleware\GetUserFromToken::class,
  'jwt.refresh' => \Tymon\JWTAuth\Middleware\RefreshToken::class,
];

```
10. Depois de todas essas configurações verificar se o Laravel tá rodando:
```
php artisan serve
```

### Implementar o Controller de Autenticação (Api Laravel)
1. Criar o controller __AuthController__ dentro de uma pasta que chamaremos de __Api__.
```
php artisan make:controller Api/AuthController
```

2. Criar o método de autenticação:
 *Na própria documentação do Laravel, em __Creating Tokens__, já tem a função authenticate pronta, copiar.*
2.1 Alterar o nome da função para __login__.
```
public function login(Request $request)
{
    $credentials = $request->only('email', 'password');
    
    if (!$token = $this->jwtAuth->attempt($credentials)) {
        return response()->json(['error' => 'invalid_credentials'], 401);
    }
        
    // o jwtAuth tem um método que retorna os dados do usuário que autenticou
    $user = $this->jwtAuth->authenticate($token);

    return response()->json(compact('token', 'user'));
}
```

3. criar o método para pegar o usuário logado, na própria documentação do Laravel, em __Authentication__, já tem a função __getAuthenticatedUser__ pronta, copiar para usar como base.
3.1. Alterar o nome do método para __me__.
```
public function me()
{
    if (! $user = $this->jwtAuth->parseToken()->authenticate()) {
        return response()->json(['error' => 'user_not_found'], 404);
    }
    return response()->json(compact('user'));
}
```

4. Dentro da documentação do Laravel, em Authentication, tem uma classe __render__, Hendler.php (app/Exceptions/Handler.php) que trata todas essas exceções.
4.1. Modificar o método __render__ conforme abaixo:
```
public function render($request, Exception $exception)
{
    if ($exception instanceof \Tymon\JWTAuth\Exceptions\TokenExpiredException) {
        return response()->json(['error' => 'token_expired'], $exception->getStatusCode());
    }
    else if ($exception instanceof \Tymon\JWTAuth\Exceptions\TokenInvalidException) {
        return response()->json(['error' => 'token_invalid'], $exception->getStatusCode());
    }
    else if ($exception instanceof \Tymon\JWTAuth\Exceptions\JWTException) {
        return response()->json(['error' => $exception->getMessage()], $exception->getStatusCode());
    }
    else if ($exception instanceof \Tymon\JWTAuth\Exceptions\TokenBlacklistedException) {
        return response()->json(['error' => 'token_has_been_blacklisted'], $exception->getStatusCode());
    }
    return parent::render($request, $exception);
}
```

5. Para não precisar usar a classe JTWAuth de forma estática (JTWAuth::método), assim usaremos __$this->jwtAuth->__ ao invés de __JTWAuth::__. Criar um construtor conforme abaixo:
5.1. Importar a classe __use Tymon\JWTAuth\JTWAuth;__
5.2. Criar o construtor conforme abaixo:
```
/**
* @var JWTAuth
*/
private $jwtAuth;

public function __construct(JWTAuth $jwtAuth)
{
    $this->jwtAuth = $jwtAuth;
}
```

6. Criar o método refresh que irá fazer o refresh token.
```
public function refresh()
{
    $token = $this->jwtAuth->getToken();
    $token = $this->jwtAuth->refresh($token);

    return response()->json(compact('token'));
}
```

7. Criar o método __logout__.
```
public function logout()
{
    $token = $this->jwtAuth->getToken();
    $this->jwtAuth->invalidate($token);

    return response()->json('logout');
}
```

### Crianr as rotas e testar os métodos
1. abrir o arquivo __api.php__ que fica dentro da pasta __routes__ e criar a rota para login.
```
Route::post('auth/login', 'Api\AuthController@login');
```

Onde:
 - __auth/login__ -> rota
 - __Api/AuthController__ -> path do controller
 - __login__ -> método
 
__Teste a rota no Postman para ver se o token tá sendo retornado, para isso é necessário rodar o servidor antes.__
```
php artisan serve
```

2. Criar um __Grupo de Rotas__ através de um __middleware__.
 Em __middleware__ >> __kernel.php__ foi criado o __jwt.auth__, ao passarmos esse middleware em nosso grupo de rotas estamos dizendo para aplicação que a rota necessita do token de autenticação.
```
Route::group(['middleware' => 'jwt.auth', 'namespace' => 'Api\\'], function () {
    Route::get('auth/me', 'AuthController@me');
});
```

__Teste a rota no Postman, primeiro sem passar o token no header e depois passando o token no Header__.
Cabeçalho no Postman:
 - __Headers__
 -- __key__: Authorization
 -- __Value__: Bearer TOKEN
 
__OBS.:__ O Mesmo teste pode ser feito para o refresh e logout.

### Instalando Angular e AdminLTE
Podemos criar uma aplicação angular do zero com ng-CLI (ng new my-app), porém iremos utilizar um painel pronto, o [AdminLTE](https://adminlte.io/) através do seu repositório no [GitHub](https://github.com/csotomon/Angular2-AdminLTE).
1. Copiar a url para clonar o AdminLTE na pasta raiz do nosso projeto (fora da pasta api que criamos).
```
git clone https://github.com/csotomon/Angular2-AdminLTE.git
```
2. Renomear a pasta da aplicação criada para “web”.
3. Rodar o __npm install__.
4. Dentro da pasta __web/src/environments__, no arquivo __environment.ts__, onde criamos nossas constantes no Angular, vamos criar uma constante para nossa api.
```
api_url: 'http://localhost:8000/api'
```
__OBS.:__ No arquivo __environment.prod.ts__ definimos as urls de produção.

### Alterando as rotas
__Vamos usar somente a parte do painel, onde todas as seções, exceto o Login, serão privadas.__
1. Em __app.modules.ts__ limpar e deixar apenas o __AppComponent__, com isso não vamos mais carregar os __starter__.
2. Em app criar o módulo __auth__, que usaremos para autenticação:
```
ng g module auth
```
* importar no app.modules.ts.
3. Dentro da pasta do módulo auth vamos criar um componente chamado __login__ e declará-lo no módulo auth.
```
ng g component auth/login
```
4. Trocar as rotas da aplicação inicial em __app/app-routing/app-routing.modules.ts__.
```
import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';

import { LoginComponent } from '../auth/login/login.component';

@NgModule({
  imports: [
    RouterModule.forRoot([
      { path: '', redirectTo: 'admin', pathMatch: 'full' },
      { path: 'auth/login', component: LoginComponent },
    ])
  ],
  declarations: [],
  exports: [ RouterModule]
})
export class AppRoutingModule { }
```

### Formulário de login
1. Criar o formGroup no component login;
2. Importar o módulo ReactiveFormsModule no auth.module.ts
3. Criar o formulário login.component.html
__HTML__
```
<div class="container app-login">
  <div class="row">
    <div class="col-xs-12 col-md-6 col-md-offset-3">
      <div class="panel panel-default">
        <div class="panel-body">
          <h1 class="text-center">
            <b>TJG</b> Web
            <br/>
            <small>Área Restrita</small>
          </h1>
          <br/>
          <div class="alert alert-danger alert-dismissible" role="alert" *ngIf="errorCredentials">
            <button type="button" class="close" data-dismiss="alert" aria-label="Close">
              <span aria-hidden="true">&times;</span>
            </button>
            Usuário ou senha inválidos.
          </div>
          <form [formGroup]="f" novalidate>
            <div class="form-group has-feedback" [ngClass]="{'has-success': f.controls['email'].valid,
                'has-error': f.controls['email'].invalid && (f.controls['email'].touched || f.controls['email'].dirty)}">
              <input type="email" formControlName="email" class="form-control" id="InputEmail" placeholder="Email">
              <span *ngIf="f.controls['email'].valid" class="glyphicon glyphicon-ok form-control-feedback" aria-hidden="true"></span>
              <span *ngIf="f.controls['email'].invalid && (f.controls['email'].touched || f.controls['email'].dirty)">
                <span class="glyphicon glyphicon-remove form-control-feedback" aria-hidden="true"></span>
                <span class="text-danger">E-mail inválido.</span>
              </span>
            </div>
            <div class="form-group" [ngClass]="{'has-success': f.controls['password'].valid,
                 'has-error': f.controls['password'].invalid && (f.controls['password'].touched || f.controls['password'].dirty)}">
              <input type="password" formControlName="password" class="form-control" id="InputPassword" placeholder="Password">
              <span class="text-danger" *ngIf="f.controls['password'].invalid && (f.controls['password'].touched || f.controls['password'].dirty)">Campo obrigatório.</span>
            </div>
            <button type="submit" class="btn btn-default" [disabled]="f.invalid" (click)="onSubmit()">Entrar</button>
          </form>
        </div>
      </div>
    </div>
  </div>
</div>
```

__CSS__
```
.app-login .row{margin-top: 20vh;}
.app-login .panel-body{box-shadow: 0px 0px 10px 3px #ccc;}
```

### Criando serviço de autenticação
1. criar, na pasta __auth__, o serviço que validará as rotas.
```
ng g service services/auth
```
2. Registrar o serviço no módulo auth:
```
@NgModule({
 imports: [
   CommonModule,
   ReactiveFormsModule
 ],
 declarations: [
   LoginComponent
 ],
 providers: [
   AuthService
 ]
})
```
3. No serviço de autenticação criar o método de login que receberá as informações do formulário e requisitará a autenticação a Api;
4. Importar o __HttpClient__ que fará nossas requisições a Api;
5. Importar o __environment__ onde declaramos nossas constantes;
```
login(credentials: {email: string, password: string}) {
   return this.http.post('${environment.api_url}/auth/login', credentials);
 }
```
6. No componente login, chamar o serviço de autenticação, método login.
    - No construtor importar o serviço de autenticação

 ### Ativando CORS no Laravel
Instalar a biblioteca [https://github.com/barryvdh/laravel-cors](https://github.com/barryvdh/laravel-cors) na nossa Api.
```
composer require barryvdh/laravel-cors
```
2. Registrar um grupo de middleware:
*Podemos registar de forma __global__, __web__ ou __api__, como estamos usando o laravel somente como __api__ é nela que iremos registrar.*
```
Api / App / Http / Kernel.php
\Barryvdh\Cors\HandleCors::class
```
Publicar o arquivo de configuração que será gerado na pasta __config__.
```
php artisan vendor:publish --provider="Barryvdh\Cors\ServiceProvider"
```
O arquivo gerado foi o __cors.php__ nele serão feitas as configurações de cabeçalho.
Liberar a proteção __CSRF__, em *Api / App / Http / Middleware / VerifyCsrfToken*
```
protected $except = [
    'api/*'
];
```
### Armazenando token

1. No método __login__ interceptar a resposta com o __.do()__, para usar esse método será preciso tipar a requisição post, usar o __<any>__.
2. Criar um __hash base 64__ para os dados do usuário que ficará no localStorage, usar o método __btoa()__ para isso.
3. No componente login serão tratados os erros caso ocorra.
4. Criar no serviço o método que checa se o usuário tá logado.

#### Finalizando AuthService e Mostrando dados do usuário
1. Criar uma interface (model) para o nosso user;
```
export interface User {
id: number;
name: string;
email: string;
created_at: string;
updated_at: string;
}
```
### Guarda de Rotas
1. Criar um serviço para os __*guardas*__ das nossas rotas;
```
ng g service guards/auth
```
2. Renomear o arquivo de __auth.service.ts__ para __auth.guard.ts__ e o nome da classe de __AuthService__ para __AuthGuard__ de acordo com o style guide do Angular.
*O site do Angular, em Guards, ele mostra algumas interfaces, use a __CanActivate__*.

2. Implementar a classe AuthGuard a esse método.
```
import { Observable } from 'rxjs/Observable';
import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, Router, CanActivateChild } from '@angular/router';
import { AuthService } from './../auth/services/auth.service';

@Injectable()
export class AuthGuard implements CanActivate, CanActivateChild {

 constructor(private auth: AuthService, private router: Router) { }

 canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<boolean> | Promise<boolean> | boolean {
   if ( this.auth.check() ) {
     return true;
   }
   this.router.navigate(['auth/login']);
   return false;
 }

 canActivateChild(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<boolean> | Promise<boolean> | boolean {
   if ( this.auth.check() ) {
     return true;
   }
   this.router.navigate(['auth/login']);
   return false;
 }

}
```
__Como ele será um serviço global, importá-lo no provider do app.module.__

4. Nas rotas de administrador *(admin/admin-routing)* inserir o serviço de guardião de rotas.
```
import { AdminDashboard2Component } from './../admin-dashboard2/admin-dashboard2.component';
import { AdminDashboard1Component } from './../admin-dashboard1/admin-dashboard1.component';
import { AdminComponent } from './../admin.component';
import { NgModule, Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';

import { AuthGuard } from '../../guards/auth.guard';

@NgModule({
 imports: [
   RouterModule.forChild([
     {
       path: 'admin',
       component: AdminComponent, canActivate: [AuthGuard], canActivateChild: [AuthGuard],
       children: [
         {
           path: '',
           redirectTo: 'dashboard1',
           pathMatch: 'full'
         },
         {
           path: 'dashboard1',
           component: AdminDashboard1Component
         },
         {
           path: 'dashboard2',
           component: AdminDashboard2Component
         }
       ]
     }
   ])
 ],
 exports: [
   RouterModule
 ]
})
export class AdminRoutingModule { }
```
__OBS.:__ Essa verificação não está segura, pois se o usuário criar direto no localStorage um usuário com um valor qualquer ele vai ter acesso a rota restrita, pois tá verificando apenas se existe a sessão user.

### Adicionando token no header da requisição

O __intercept__ foi incluído a partir da versão 4.3 do Angular, usar o mesmo para evitar de passar em toda requisição um options com o header.

1. Em app criar um diretório chamado __interceptors__ e dentro dele um arquivo chamado __token.interceptor.ts__;
2. Copiar o código da documentação do angular *(FUNTAMENTALS >> HttpClient >> Intercepting requests and responses)*: [https://angular.io/guide/http#intercepting-requests-and-responses](https://angular.io/guide/http#intercepting-requests-and-responses)
3. Alterar o nome da classe para __TokenInterceptor__, o que essa classe irá fazer?
Sempre que tiver uma requisição, ela irá interceptar essa requisição e adicionar o Token ao header da requisição.
```
import { Injectable } from '@angular/core';
import { HttpEvent, HttpInterceptor, HttpHandler, HttpRequest } from '@angular/common/http';
import { Observable } from 'rxjs/Observable';
import { environment } from '../../environments/environment';

/** Pass untouched request through to the next request handler. */
@Injectable()
export class TokenInterceptor implements HttpInterceptor {

 intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
   const requestUrl: Array<any> = request.url.split('/');
   const apiUrl: Array<any> = environment.api_url.split('/');
   const token = localStorage.getItem('token');
   /* verifica se a requisição é para a api da aplicação */
   if (token && (requestUrl[2] === apiUrl[2])) {
     const newRequest = request.clone({ setHeaders: {'Authorization': `Bearer ${token}`} });
     return next.handle(newRequest);
   }else {
     return next.handle(request);
   }
 }

}
```
__OBS.:__ Esse conceito de __interceptor__ funciona com o mesmo conceito do __middleware__ do Laravel.

4. Importar nosso interceptor no app.module:
```
providers: [
   AuthGuard,
   { provide: HTTP_INTERCEPTORS, useClass: TokenInterceptor, multi: true },
 ],
```

### Refresh Token

1. Duplicar o __token.interception.ts__ e renomear para __refresh-token.interception.ts__.
Ao contrário do __token.interception__, que intercepta o request antes da requisição, o __refresh-token.interception__ irá interceptar após a requisição, utilizando o operador __catch do rxjs__, se o token estiver expirado ele fará uma nova requisição para atualizar o token, se o tempo limite de expiração do token não tiver expirado ele carrega os dados de acordo com a requisição.
__Para repetir a primeira requisição após requisitar a atualização do token é usado o operador flatMap do rxjs.__
```
import { Injectable, Injector } from '@angular/core';
import { HttpEvent, HttpInterceptor, HttpHandler, HttpRequest, HttpErrorResponse, HttpClient } from '@angular/common/http';
import { environment } from './../../environments/environment';
// tslint:disable-next-line:import-blacklist
import { Observable } from 'rxjs/Rx';

@Injectable()
export class RefreshTokenInterceptor implements HttpInterceptor {

 constructor(private injector: Injector) {}

 intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {

   return next.handle(request).catch((errorResponse: HttpErrorResponse) => {
     const error = (typeof errorResponse.error !== 'object') ? JSON.parse(errorResponse.error) : errorResponse;

     if (errorResponse.status === 401 && error.error === 'token_expired') {
       const http = this.injector.get(HttpClient);

       return http.post<any>(`${environment.api_url}/auth/refresh`, {})
         .flatMap(data => {
           localStorage.setItem('token', data.token);
           const cloneRequest = request.clone({setHeaders: {'Authorization': `Bearer ${data.token}`}});

           return next.handle(cloneRequest);
         });
     }

     return Observable.throw(errorResponse);
   });

 }
}
```

### Tratando outros erros de token
Criar na raiz do app um arquivo chamado __app.error-handle.ts__, nele será tratado outros erros de token retornados do handle da nossa api.
```
import { Router } from '@angular/router';
import { HttpErrorResponse } from '@angular/common/http';
import { Injectable, ErrorHandler, Injector } from '@angular/core';

@Injectable()
export class AplicationErrorHandle extends ErrorHandler {

  constructor(private injector: Injector) {
    super();
  }

  handleError(errorResponse: HttpErrorResponse | any) {
    if (errorResponse instanceof HttpErrorResponse) {
      const error = (typeof errorResponse.error !== 'object') ? JSON.parse(errorResponse.error) : errorResponse.error;

      if (errorResponse.status === 400 &&
        (error.error === 'token_expired' || error.error === 'token_invalid' ||
          error.error === 'A token is required' || error.error === 'token_not_provided')) {
        this.goToLogin();
      }

      if (errorResponse.status === 401 && error.error === 'token_has_been_blacklisted') {
        this.goToLogin();
      }

    }

    super.handleError(errorResponse);
  }

  goToLogin(): void {
    const router = this.injector.get(Router);
    router.navigate(['auth/login']);
  }

}

```