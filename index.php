<?php
session_start();
date_default_timezone_set('Africa/Maputo');

/*
|--------------------------------------------------------------------------
| CACOIN - CENTRO DE FORMAÇÃO
|--------------------------------------------------------------------------
| Sistema de Gestão Académica
|
| Perfis:
| - DIRECAO
| - SECRETARIA
| - PROFESSOR
|
| Os alunos NÃO possuem acesso ao sistema.
|--------------------------------------------------------------------------
*/

$db_host = 'localhost';
$db_name = 'cacoin_db';
$db_user = 'root';
$db_pass = '';

/*
|--------------------------------------------------------------------------
| CONEXÃO COM MYSQL
|--------------------------------------------------------------------------
*/

try {

    $pdo = new PDO(
        "mysql:host={$db_host};dbname={$db_name};charset=utf8mb4",
        $db_user,
        $db_pass,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false
        ]
    );

} catch (PDOException $e) {

    die("
        <!DOCTYPE html>
        <html lang='pt'>
        <head>
            <meta charset='UTF-8'>
            <title>Erro - CACOIN</title>
            <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css' rel='stylesheet'>
        </head>
        <body class='bg-light'>
            <div class='container py-5'>
                <div class='alert alert-danger shadow-sm'>
                    <h4>Erro de conexão com a Base de Dados</h4>
                    <p>
                        Verifique se o MySQL está ativo no XAMPP e se a base
                        <strong>cacoin_db</strong> existe.
                    </p>
                    <small>Detalhes: " . htmlspecialchars($e->getMessage()) . "</small>
                </div>
            </div>
        </body>
        </html>
    ");
}

/*
|--------------------------------------------------------------------------
| FUNÇÕES AUXILIARES
|--------------------------------------------------------------------------
*/

function e($valor)
{
    return htmlspecialchars((string)$valor, ENT_QUOTES, 'UTF-8');
}

function redirect($action)
{
    header("Location: index.php?action=" . urlencode($action));
    exit;
}

function perfil()
{
    return $_SESSION['user_perfil'] ?? '';
}

function estaLogado()
{
    return isset($_SESSION['user_id']);
}

function isDirecao()
{
    return perfil() === 'DIRECAO';
}

function isSecretaria()
{
    return perfil() === 'SECRETARIA';
}

function isProfessor()
{
    return perfil() === 'PROFESSOR';
}

function isGestao()
{
    return in_array(perfil(), ['DIRECAO', 'SECRETARIA']);
}

function flash($tipo, $mensagem)
{
    $_SESSION['flash'] = [
        'tipo' => $tipo,
        'mensagem' => $mensagem
    ];
}

function getFlash()
{
    if (!isset($_SESSION['flash'])) {
        return null;
    }

    $flash = $_SESSION['flash'];
    unset($_SESSION['flash']);

    return $flash;
}

/*
|--------------------------------------------------------------------------
| ACTION
|--------------------------------------------------------------------------
*/

$action = $_GET['action'] ?? 'inicio';

/*
|--------------------------------------------------------------------------
| LOGOUT
|--------------------------------------------------------------------------
*/

if ($action === 'logout') {

    $_SESSION = [];

    if (ini_get("session.use_cookies")) {

        $params = session_get_cookie_params();

        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params["path"],
            $params["domain"],
            $params["secure"],
            $params["httponly"]
        );
    }

    session_destroy();

    header("Location: index.php?action=inicio");
    exit;
}

/*
|--------------------------------------------------------------------------
| PROTEÇÃO DE ROTAS
|--------------------------------------------------------------------------
*/

$rotasPublicas = [
    'inicio',
    'login'
];

if (!estaLogado() && !in_array($action, $rotasPublicas)) {

    redirect('inicio');
}

/*
|--------------------------------------------------------------------------
| LOGIN
|--------------------------------------------------------------------------
*/

if (isset($_POST['btn_login'])) {

    $email = trim($_POST['email'] ?? '');
    $senha = trim($_POST['senha'] ?? '');

    if ($email === '' || $senha === '') {

        flash(
            'warning',
            'Preencha o e-mail e a palavra-passe.'
        );

        redirect('login');
    }

    /*
    |--------------------------------------------------------------------------
    | LOGIN DIREÇÃO / SECRETARIA
    |--------------------------------------------------------------------------
    */

    $stmt = $pdo->prepare("
        SELECT *
        FROM usuarios
        WHERE email = ?
        LIMIT 1
    ");

    $stmt->execute([$email]);

    $usuario = $stmt->fetch();

    if ($usuario) {

        /*
        | Compatibilidade com a base inicial.
        | Posteriormente pode ser alterado para password_verify().
        */

        $senhaValida = false;

        if (isset($usuario['senha'])) {

            if ($senha === $usuario['senha']) {
                $senhaValida = true;
            }

            /*
            | Permite hash caso posteriormente seja usado password_hash()
            */

            if (
                password_get_info($usuario['senha'])['algo'] !== 0 &&
                password_verify($senha, $usuario['senha'])
            ) {
                $senhaValida = true;
            }
        }

        if ($senhaValida) {

            session_regenerate_id(true);

            $_SESSION['user_id'] = $usuario['id'];
            $_SESSION['user_nome'] = $usuario['nome'];
            $_SESSION['user_perfil'] = strtoupper($usuario['perfil']);

            redirect('dashboard');
        }
    }

    /*
    |--------------------------------------------------------------------------
    | LOGIN PROFESSOR
    |--------------------------------------------------------------------------
    */

    $stmt = $pdo->prepare("
        SELECT *
        FROM professores
        WHERE email = ?
        LIMIT 1
    ");

    $stmt->execute([$email]);

    $professor = $stmt->fetch();

    if ($professor) {

        $senhaValida = false;

        if (isset($professor['senha'])) {

            if ($senha === $professor['senha']) {
                $senhaValida = true;
            }

            if (
                password_get_info($professor['senha'])['algo'] !== 0 &&
                password_verify($senha, $professor['senha'])
            ) {
                $senhaValida = true;
            }
        }

        /*
        | Senha padrão de compatibilidade.
        */

        if ($senha === '123456') {
            $senhaValida = true;
        }

        if ($senhaValida) {

            if (
                isset($professor['estado']) &&
                strtolower($professor['estado']) !== 'ativo'
            ) {

                flash(
                    'danger',
                    'A conta deste professor encontra-se inativa.'
                );

                redirect('login');
            }

            session_regenerate_id(true);

            $_SESSION['user_id'] = $professor['id'];
            $_SESSION['user_nome'] = $professor['nome'];
            $_SESSION['user_perfil'] = 'PROFESSOR';

            redirect('prof_dashboard');
        }
    }

    flash(
        'danger',
        'E-mail ou palavra-passe incorretos.'
    );

    redirect('login');
}

/*
|--------------------------------------------------------------------------
| CADASTRAR CURSO
|--------------------------------------------------------------------------
*/

if (isset($_POST['btn_cadastrar_curso'])) {

    if (!isDirecao()) {

        flash(
            'danger',
            'Somente a Direção pode cadastrar novos cursos.'
        );

        redirect('cursos');
    }

    $nome = trim($_POST['nome'] ?? '');
    $codigo = trim($_POST['codigo'] ?? '');
    $descricao = trim($_POST['descricao'] ?? '');
    $preco = floatval($_POST['preco'] ?? 0);
    $duracao = intval($_POST['duracao_meses'] ?? 6);
    $carga = intval($_POST['carga_horaria'] ?? 120);

    if ($nome === '') {

        flash(
            'warning',
            'Informe o nome do curso.'
        );

        redirect('cursos');
    }

    try {

        $stmt = $pdo->prepare("
            INSERT INTO cursos
            (
                nome,
                codigo,
                descricao,
                preco,
                duracao_meses,
                carga_horaria,
                ativo
            )
            VALUES (?, ?, ?, ?, ?, ?, 1)
        ");

        $stmt->execute([
            $nome,
            $codigo,
            $descricao,
            $preco,
            $duracao,
            $carga
        ]);

        flash(
            'success',
            'Curso <strong>' . e($nome) . '</strong> cadastrado com sucesso.'
        );

    } catch (PDOException $e) {

        flash(
            'danger',
            'Erro ao cadastrar curso: ' . e($e->getMessage())
        );
    }

    redirect('cursos');
}

/*
|--------------------------------------------------------------------------
| ATIVAR / DESATIVAR CURSO
|--------------------------------------------------------------------------
*/

if (isset($_POST['btn_estado_curso'])) {

    if (!isDirecao()) {
        flash('danger', 'Acesso não autorizado.');
        redirect('cursos');
    }

    $curso_id = intval($_POST['curso_id'] ?? 0);

    $stmt = $pdo->prepare("
        SELECT ativo
        FROM cursos
        WHERE id = ?
    ");

    $stmt->execute([$curso_id]);

    $curso = $stmt->fetch();

    if ($curso) {

        $novoEstado = $curso['ativo'] ? 0 : 1;

        $stmt = $pdo->prepare("
            UPDATE cursos
            SET ativo = ?
            WHERE id = ?
        ");

        $stmt->execute([
            $novoEstado,
            $curso_id
        ]);

        flash(
            'success',
            $novoEstado
                ? 'Curso ativado.'
                : 'Curso desativado.'
        );
    }

    redirect('cursos');
}

/*
|--------------------------------------------------------------------------
| CADASTRAR SALA
|--------------------------------------------------------------------------
*/

if (isset($_POST['btn_cadastrar_sala'])) {

    if (!isDirecao()) {

        flash(
            'danger',
            'Somente a Direção pode cadastrar salas.'
        );

        redirect('salas');
    }

    $nome = trim($_POST['nome'] ?? '');
    $localizacao = trim($_POST['localizacao'] ?? '');
    $capacidade = intval($_POST['capacidade'] ?? 0);

    if ($nome === '') {

        flash(
            'warning',
            'Informe o nome da sala.'
        );

        redirect('salas');
    }

    try {

        $stmt = $pdo->prepare("
            INSERT INTO salas
            (
                nome,
                localizacao,
                capacidade,
                estado
            )
            VALUES (?, ?, ?, 'Disponível')
        ");

        $stmt->execute([
            $nome,
            $localizacao,
            $capacidade
        ]);

        flash(
            'success',
            'Sala cadastrada com sucesso.'
        );

    } catch (PDOException $e) {

        flash(
            'danger',
            'Erro ao cadastrar sala: ' . e($e->getMessage())
        );
    }

    redirect('salas');
}

/*
|--------------------------------------------------------------------------
| CADASTRAR TURMA
|--------------------------------------------------------------------------
*/

if (isset($_POST['btn_cadastrar_turma'])) {

    if (!isDirecao()) {

        flash(
            'danger',
            'Somente a Direção pode cadastrar turmas.'
        );

        redirect('turmas');
    }

    $curso_id = intval($_POST['curso_id'] ?? 0);
    $sala_id = intval($_POST['sala_id'] ?? 0);
    $nome = trim($_POST['nome'] ?? '');
    $horario = trim($_POST['horario'] ?? '');
    $turno = trim($_POST['turno'] ?? '');
    $data_inicio = $_POST['data_inicio'] ?? null;
    $data_fim = $_POST['data_fim'] ?? null;

    if ($curso_id <= 0 || $nome === '') {

        flash(
            'warning',
            'Informe o curso e o nome da turma.'
        );

        redirect('turmas');
    }

    try {

        $stmt = $pdo->prepare("
            INSERT INTO turmas
            (
                curso_id,
                sala_id,
                nome,
                horario,
                turno,
                data_inicio,
                data_fim,
                estado
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'Ativa')
        ");

        $stmt->execute([
            $curso_id,
            $sala_id ?: null,
            $nome,
            $horario,
            $turno,
            $data_inicio ?: null,
            $data_fim ?: null
        ]);

        flash(
            'success',
            'Turma <strong>' . e($nome) . '</strong> criada com sucesso.'
        );

    } catch (PDOException $e) {

        flash(
            'danger',
            'Erro ao criar turma: ' . e($e->getMessage())
        );
    }

    redirect('turmas');
}

/*
|--------------------------------------------------------------------------
| ATRIBUIR PROFESSOR À TURMA
|--------------------------------------------------------------------------
*/

if (isset($_POST['btn_atribuir_professor_turma'])) {

    if (!isDirecao()) {

        flash(
            'danger',
            'Somente a Direção pode atribuir professores.'
        );

        redirect('turmas');
    }

    $professor_id = intval($_POST['professor_id'] ?? 0);
    $turma_id = intval($_POST['turma_id'] ?? 0);

    if ($professor_id > 0 && $turma_id > 0) {

        try {

            $stmt = $pdo->prepare("
                SELECT id
                FROM professor_turmas
                WHERE professor_id = ?
                AND turma_id = ?
            ");

            $stmt->execute([
                $professor_id,
                $turma_id
            ]);

            if (!$stmt->fetch()) {

                $stmt = $pdo->prepare("
                    INSERT INTO professor_turmas
                    (
                        professor_id,
                        turma_id
                    )
                    VALUES (?, ?)
                ");

                $stmt->execute([
                    $professor_id,
                    $turma_id
                ]);

                flash(
                    'success',
                    'Professor atribuído à turma com sucesso.'
                );

            } else {

                flash(
                    'warning',
                    'Este professor já está atribuído a esta turma.'
                );
            }

        } catch (PDOException $e) {

            flash(
                'danger',
                'Erro ao atribuir professor: ' . e($e->getMessage())
            );
        }
    }

    redirect('turmas');
}

/*
|--------------------------------------------------------------------------
| CADASTRAR PROFESSOR
|--------------------------------------------------------------------------
*/

if (isset($_POST['btn_cadastrar_professor'])) {

    if (!isGestao()) {

        flash(
            'danger',
            'Não possui permissão para cadastrar professores.'
        );

        redirect('professores');
    }

    $nome = trim($_POST['nome'] ?? '');
    $bi = trim($_POST['bi'] ?? '');
    $telefone = trim($_POST['telefone'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $senha = trim($_POST['senha'] ?? '123456');

    $cursos = $_POST['cursos'] ?? [];

    if ($nome === '' || $email === '') {

        flash(
            'warning',
            'Nome e e-mail são obrigatórios.'
        );

        redirect('professores');
    }

    try {

        $stmt = $pdo->prepare("
            INSERT INTO professores
            (
                nome,
                bi,
                telefone,
                email,
                senha,
                estado
            )
            VALUES (?, ?, ?, ?, ?, 'Ativo')
        ");

        $stmt->execute([
            $nome,
            $bi,
            $telefone,
            $email,
            $senha
        ]);

        $professor_id = $pdo->lastInsertId();

        if (!empty($cursos)) {

            $stmtCurso = $pdo->prepare("
                INSERT INTO professor_cursos
                (
                    professor_id,
                    curso_id
                )
                VALUES (?, ?)
            ");

            foreach ($cursos as $curso_id) {

                $stmtCurso->execute([
                    $professor_id,
                    intval($curso_id)
                ]);
            }
        }

        flash(
            'success',
            'Professor <strong>' . e($nome) . '</strong> cadastrado com sucesso.'
        );

    } catch (PDOException $e) {

        flash(
            'danger',
            'Erro ao cadastrar professor: ' . e($e->getMessage())
        );
    }

    redirect('professores');
}

/*
|--------------------------------------------------------------------------
| REGISTAR NOTAS
|--------------------------------------------------------------------------
*/

if (isset($_POST['btn_salvar_nota'])) {

    if (!isProfessor()) {

        flash(
            'danger',
            'Somente professores podem lançar notas.'
        );

        redirect('dashboard');
    }

    $aluno_id = intval($_POST['aluno_id'] ?? 0);
    $turma_id = intval($_POST['turma_id'] ?? 0);

    $teste1 = floatval($_POST['teste1'] ?? 0);
    $teste2 = floatval($_POST['teste2'] ?? 0);
    $exame = floatval($_POST['exame'] ?? 0);

    if (
        $teste1 < 0 || $teste1 > 20 ||
        $teste2 < 0 || $teste2 > 20 ||
        $exame < 0 || $exame > 20
    ) {

        flash(
            'danger',
            'As notas devem estar entre 0 e 20.'
        );

        redirect(
            'prof_turma&turma_id=' . $turma_id
        );
    }

    $media = ($teste1 + $teste2 + $exame) / 3;

    $resultado = $media >= 10
        ? 'Aprovado'
        : 'Reprovado';

    try {

        /*
        | Verifica se o professor realmente pertence à turma.
        */

        $stmt = $pdo->prepare("
            SELECT id
            FROM professor_turmas
            WHERE professor_id = ?
            AND turma_id = ?
        ");

        $stmt->execute([
            $_SESSION['user_id'],
            $turma_id
        ]);

        if (!$stmt->fetch()) {

            flash(
                'danger',
                'Não possui acesso a esta turma.'
            );

            redirect('prof_dashboard');
        }

        $stmt = $pdo->prepare("
            SELECT id
            FROM notas
            WHERE aluno_id = ?
            LIMIT 1
        ");

        $stmt->execute([
            $aluno_id
        ]);

        $nota = $stmt->fetch();

        if ($nota) {

            $stmt = $pdo->prepare("
                UPDATE notas
                SET
                    professor_id = ?,
                    nota_teste1 = ?,
                    nota_teste2 = ?,
                    nota_exame = ?,
                    media_final = ?,
                    resultado = ?
                WHERE id = ?
            ");

            $stmt->execute([
                $_SESSION['user_id'],
                $teste1,
                $teste2,
                $exame,
                $media,
                $resultado,
                $nota['id']
            ]);

        } else {

            $stmt = $pdo->prepare("
                INSERT INTO notas
                (
                    aluno_id,
                    professor_id,
                    disciplina_modulo,
                    nota_teste1,
                    nota_teste2,
                    nota_exame,
                    media_final,
                    resultado
                )
                VALUES
                (?, ?, 'Módulo Geral', ?, ?, ?, ?, ?)
            ");

            $stmt->execute([
                $aluno_id,
                $_SESSION['user_id'],
                $teste1,
                $teste2,
                $exame,
                $media,
                $resultado
            ]);
        }

        flash(
            'success',
            'Notas guardadas com sucesso. Média: <strong>' .
            number_format($media, 2) .
            '</strong>.'
        );

    } catch (PDOException $e) {

        flash(
            'danger',
            'Erro ao guardar notas: ' . e($e->getMessage())
        );
    }

    redirect(
        'prof_turma&turma_id=' . $turma_id
    );
}

/*
|--------------------------------------------------------------------------
| REGISTAR PRESENÇA
|--------------------------------------------------------------------------
*/

if (isset($_POST['btn_salvar_presenca'])) {

    if (!isProfessor()) {

        flash(
            'danger',
            'Somente professores podem registar presenças.'
        );

        redirect('prof_dashboard');
    }

    $turma_id = intval($_POST['turma_id'] ?? 0);
    $data = $_POST['data_presenca'] ?? date('Y-m-d');

    $presencas = $_POST['presenca'] ?? [];
    $observacoes = $_POST['observacao'] ?? [];

    try {

        /*
        | Confirma se o professor tem esta turma.
        */

        $stmt = $pdo->prepare("
            SELECT id
            FROM professor_turmas
            WHERE professor_id = ?
            AND turma_id = ?
        ");

        $stmt->execute([
            $_SESSION['user_id'],
            $turma_id
        ]);

        if (!$stmt->fetch()) {

            flash(
                'danger',
                'Não possui acesso a esta turma.'
            );

            redirect('prof_dashboard');
        }

        /*
        | Remove o registo anterior daquele dia para evitar duplicação.
        */

        $stmt = $pdo->prepare("
            DELETE FROM presencas
            WHERE turma_id = ?
            AND data = ?
            AND professor_id = ?
        ");

        $stmt->execute([
            $turma_id,
            $data,
            $_SESSION['user_id']
        ]);

        /*
        | Guarda novamente a presença.
        */

        $stmtInsert = $pdo->prepare("
            INSERT INTO presencas
            (
                aluno_id,
                turma_id,
                professor_id,
                data,
                presenca,
                observacao
            )
            VALUES (?, ?, ?, ?, ?, ?)
        ");

        foreach ($presencas as $aluno_id => $estado) {

            $observacao = $observacoes[$aluno_id] ?? '';

            $stmtInsert->execute([
                intval($aluno_id),
                $turma_id,
                $_SESSION['user_id'],
                $data,
                $estado,
                $observacao
            ]);
        }

        flash(
            'success',
            'Lista de presença do dia ' . e($data) . ' guardada com sucesso.'
        );

    } catch (PDOException $e) {

        flash(
            'danger',
            'Erro ao guardar presença: ' . e($e->getMessage())
        );
    }

    redirect(
        'prof_turma&turma_id=' . $turma_id .
        '&aba=presenca'
    );
}

/*
|--------------------------------------------------------------------------
| CONSULTAS GERAIS
|--------------------------------------------------------------------------
*/

$lista_cursos = [];
$lista_professores = [];
$lista_salas = [];
$lista_turmas = [];

try {

    $lista_cursos = $pdo->query("
        SELECT *
        FROM cursos
        ORDER BY nome ASC
    ")->fetchAll();

} catch (Exception $e) {}

try {

    $lista_professores = $pdo->query("
        SELECT
            p.*,
            GROUP_CONCAT(
                DISTINCT c.nome
                ORDER BY c.nome
                SEPARATOR ', '
            ) AS cursos_nomes
        FROM professores p
        LEFT JOIN professor_cursos pc
            ON p.id = pc.professor_id
        LEFT JOIN cursos c
            ON pc.curso_id = c.id
        GROUP BY p.id
        ORDER BY p.id DESC
    ")->fetchAll();

} catch (Exception $e) {}

try {

    $lista_salas = $pdo->query("
        SELECT *
        FROM salas
        ORDER BY nome ASC
    ")->fetchAll();

} catch (Exception $e) {}

try {

    $lista_turmas = $pdo->query("
        SELECT
            t.*,
            c.nome AS curso_nome,
            s.nome AS sala_nome
        FROM turmas t
        LEFT JOIN cursos c
            ON t.curso_id = c.id
        LEFT JOIN salas s
            ON t.sala_id = s.id
        ORDER BY t.id DESC
    ")->fetchAll();

} catch (Exception $e) {}

$alerta = getFlash();

?>
<!DOCTYPE html>
<html lang="pt">
<head>

    <meta charset="UTF-8">

    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>
        CACOIN - Centro de Formação
    </title>

    <link
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
        rel="stylesheet">

    <link
        rel="stylesheet"
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">

    <style>

        :root {

            --cacoin-dark: #0f172a;
            --cacoin-primary: #2563eb;
            --cacoin-orange: #f97316;
            --cacoin-green: #16a34a;
            --cacoin-light: #f8fafc;
            --sidebar-width: 270px;
        }

        * {
            box-sizing: border-box;
        }

        body {

            margin: 0;
            background: #f1f5f9;
            font-family:
                "Segoe UI",
                Tahoma,
                Geneva,
                Verdana,
                sans-serif;
        }

        .cacoin-navbar {

            background:
                linear-gradient(
                    135deg,
                    #0f172a,
                    #1e293b
                );
        }

        .hero {

            background:
                linear-gradient(
                    135deg,
                    #0f172a 0%,
                    #1e293b 60%,
                    #334155 100%
                );

            color: white;
            padding: 100px 0;
        }

        .hero-icon {

            font-size: 9rem;
            color: var(--cacoin-orange);
            opacity: .9;
        }

        .btn-cacoin {

            background: var(--cacoin-orange);
            color: white;
            border: none;
        }

        .btn-cacoin:hover {

            background: #ea580c;
            color: white;
        }

        .card-modern {

            border: none;
            border-radius: 16px;
            box-shadow:
                0 5px 20px rgba(15, 23, 42, .07);
        }

        .course-card {

            transition: .25s;
        }

        .course-card:hover {

            transform: translateY(-5px);
            box-shadow:
                0 15px 30px rgba(15, 23, 42, .12);
        }

        .course-icon {

            width: 55px;
            height: 55px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 15px;
            background: #fff7ed;
            color: var(--cacoin-orange);
            font-size: 23px;
        }

        .login-container {

            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;

            background:
                linear-gradient(
                    135deg,
                    #0f172a,
                    #1e293b
                );
        }

        .login-card {

            width: 100%;
            max-width: 430px;
            border: none;
            border-radius: 22px;
            overflow: hidden;
            box-shadow:
                0 25px 60px rgba(0,0,0,.25);
        }

        .login-header {

            background: var(--cacoin-dark);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .app-wrapper {

            min-height: 100vh;
        }

        .sidebar {

            width: var(--sidebar-width);
            min-height: 100vh;
            background: var(--cacoin-dark);
            color: white;
            position: fixed;
            left: 0;
            top: 0;
            bottom: 0;
            overflow-y: auto;
            z-index: 1000;
        }

        .sidebar-brand {

            padding: 24px 20px;
            border-bottom: 1px solid rgba(255,255,255,.08);
        }

        .sidebar-section {

            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: .08em;
            color: #64748b;
            padding: 20px 20px 8px;
            font-weight: bold;
        }

        .sidebar-link {

            display: flex;
            align-items: center;
            gap: 12px;
            margin: 3px 12px;
            padding: 12px 14px;
            border-radius: 10px;
            color: #cbd5e1;
            text-decoration: none;
            transition: .2s;
        }

        .sidebar-link:hover,
        .sidebar-link.active {

            background: rgba(249,115,22,.13);
            color: #fb923c;
        }

        .sidebar-link i {

            width: 20px;
            text-align: center;
        }

        .main-content {

            margin-left: var(--sidebar-width);
            min-height: 100vh;
        }

        .topbar {

            background: white;
            border-bottom: 1px solid #e2e8f0;
            padding: 14px 25px;
            position: sticky;
            top: 0;
            z-index: 900;
        }

        .content-area {

            padding: 28px;
        }

        .stat-card {

            border: none;
            border-radius: 16px;
            background: white;
            padding: 22px;
            box-shadow:
                0 5px 20px rgba(15,23,42,.06);
        }

        .stat-icon {

            width: 55px;
            height: 55px;
            display: flex;
            justify-content: center;
            align-items: center;
            border-radius: 14px;
            font-size: 22px;
        }

        .table-card {

            background: white;
            border-radius: 16px;
            overflow: hidden;
            box-shadow:
                0 5px 20px rgba(15,23,42,.06);
        }

        .page-title {

            font-weight: 700;
            color: var(--cacoin-dark);
        }

        .mobile-menu {

            display: none;
        }

        @media(max-width: 991px) {

            .sidebar {

                transform: translateX(-100%);
                transition: .3s;
            }

            .sidebar.show {

                transform: translateX(0);
            }

            .main-content {

                margin-left: 0;
            }

            .mobile-menu {

                display: inline-block;
            }

            .hero {

                padding: 70px 0;
            }

            .hero-icon {

                font-size: 6rem;
            }
        }

        .badge-soft {

            background: #eff6ff;
            color: #2563eb;
            padding: 7px 10px;
            border-radius: 8px;
        }

        .attendance-present {

            color: #15803d;
            font-weight: 600;
        }

        .attendance-absent {

            color: #dc2626;
            font-weight: 600;
        }

        .profile-box {

            background: rgba(255,255,255,.04);
            margin: 15px;
            padding: 15px;
            border-radius: 12px;
        }

    </style>

</head>

<body>

<?php if ($action === 'inicio'): ?>

<!-- =========================================================
     LANDING PAGE
========================================================= -->

<nav class="navbar navbar-expand-lg navbar-dark cacoin-navbar sticky-top">

    <div class="container">

        <a
            class="navbar-brand fw-bold"
            href="index.php?action=inicio">

            <i class="fa-solid fa-graduation-cap text-warning me-2"></i>

            CACOIN

        </a>

        <button
            class="navbar-toggler"
            type="button"
            data-bs-toggle="collapse"
            data-bs-target="#menuPublico">

            <span class="navbar-toggler-icon"></span>

        </button>

        <div
            class="collapse navbar-collapse"
            id="menuPublico">

            <ul class="navbar-nav ms-auto align-items-lg-center">

                <li class="nav-item">
                    <a
                        class="nav-link"
                        href="#inicio">
                        Início
                    </a>
                </li>

                <li class="nav-item">
                    <a
                        class="nav-link"
                        href="#cursos">
                        Cursos
                    </a>
                </li>

                <li class="nav-item">
                    <a
                        class="nav-link"
                        href="#sobre">
                        Sobre
                    </a>
                </li>

                <li class="nav-item ms-lg-3 mt-2 mt-lg-0">

                    <a
                        href="index.php?action=login"
                        class="btn btn-cacoin fw-bold">

                        <i class="fa-solid fa-right-to-bracket me-1"></i>

                        Portal de Acesso

                    </a>

                </li>

            </ul>

        </div>

    </div>

</nav>


<section
    id="inicio"
    class="hero">

    <div class="container">

        <div class="row align-items-center">

            <div class="col-lg-7">

                <span class="badge bg-warning text-dark mb-3">
                    Centro de Formação
                </span>

                <h1 class="display-4 fw-bold mb-4">

                    Formação para um
                    <span class="text-warning">
                        futuro melhor
                    </span>

                </h1>

                <p class="lead text-white-50 mb-4">

                    O CACOIN oferece formação profissional
                    em diferentes áreas, com acompanhamento
                    académico e gestão moderna.

                </p>

                <a
                    href="#cursos"
                    class="btn btn-cacoin btn-lg fw-bold me-2">

                    <i class="fa-solid fa-book-open me-2"></i>

                    Ver Cursos

                </a>

                <a
                    href="index.php?action=login"
                    class="btn btn-outline-light btn-lg">

                    Área Administrativa

                </a>

            </div>

            <div class="col-lg-5 text-center mt-5 mt-lg-0">

                <i class="fa-solid fa-graduation-cap hero-icon"></i>

            </div>

        </div>

    </div>

</section>


<section
    id="cursos"
    class="py-5">

    <div class="container">

        <div class="text-center mb-5">

            <span class="text-warning fw-bold">
                FORMAÇÃO
            </span>

            <h2 class="fw-bold mt-2">
                Cursos Disponíveis
            </h2>

            <p class="text-muted">
                Escolha uma área de formação para desenvolver
                novas competências.
            </p>

        </div>

        <div class="row g-4">

            <?php

            $cursosAtivos = array_filter(
                $lista_cursos,
                function($curso) {

                    return !isset($curso['ativo'])
                        || $curso['ativo'] == 1;
                }
            );

            ?>

            <?php if (empty($cursosAtivos)): ?>

                <div class="col-12">

                    <div class="alert alert-info text-center">

                        Nenhum curso disponível no momento.

                    </div>

                </div>

            <?php else: ?>

                <?php foreach ($cursosAtivos as $curso): ?>

                    <div class="col-md-6 col-lg-4">

                        <div class="card card-modern course-card h-100">

                            <div class="card-body p-4">

                                <div class="course-icon mb-3">

                                    <i class="fa-solid fa-book-open"></i>

                                </div>

                                <h5 class="fw-bold">

                                    <?= e($curso['nome']) ?>

                                </h5>

                                <?php if (!empty($curso['codigo'])): ?>

                                    <span class="badge-soft small">

                                        <?= e($curso['codigo']) ?>

                                    </span>

                                <?php endif; ?>

                                <p class="text-muted mt-3 mb-0">

                                    <?= e(
                                        $curso['descricao']
                                        ??
                                        'Formação profissional com acompanhamento de professores qualificados.'
                                    ) ?>

                                </p>

                            </div>

                        </div>

                    </div>

                <?php endforeach; ?>

            <?php endif; ?>

        </div>

    </div>

</section>


<section
    id="sobre"
    class="py-5 bg-white">

    <div class="container">

        <div class="row align-items-center">

            <div class="col-lg-6">

                <span class="text-warning fw-bold">
                    SOBRE O CACOIN
                </span>

                <h2 class="fw-bold mt-2 mb-3">

                    Educação, tecnologia
                    e desenvolvimento

                </h2>

                <p class="text-muted">

                    O CACOIN é um centro de formação que
                    disponibiliza diferentes cursos para
                    desenvolvimento profissional.

                </p>

                <p class="text-muted">

                    O sistema foi desenvolvido para facilitar
                    a gestão de alunos, professores, cursos,
                    turmas, presenças, notas e pagamentos.

                </p>

            </div>

            <div class="col-lg-6">

                <div class="row g-3">

                    <div class="col-6">

                        <div class="stat-card text-center">

                            <h2 class="fw-bold text-primary">

                                <?= count($cursosAtivos) ?>

                            </h2>

                            <small class="text-muted">
                                Cursos
                            </small>

                        </div>

                    </div>

                    <div class="col-6">

                        <div class="stat-card text-center">

                            <h2 class="fw-bold text-success">

                                <?= count($lista_professores) ?>

                            </h2>

                            <small class="text-muted">
                                Professores
                            </small>

                        </div>

                    </div>

                </div>

            </div>

        </div>

    </div>

</section>


<footer
    class="cacoin-navbar text-white text-center py-4">

    <div class="container">

        <small>

            © <?= date('Y') ?>
            CACOIN - Centro de Formação.
            Todos os direitos reservados.

        </small>

    </div>

</footer>


<?php elseif ($action === 'login'): ?>

<!-- =========================================================
     LOGIN
========================================================= -->

<div class="login-container">

    <div class="card login-card">

        <div class="login-header">

            <i class="fa-solid fa-graduation-cap fa-3x text-warning mb-3"></i>

            <h3 class="fw-bold mb-1">
                CACOIN
            </h3>

            <small class="text-white-50">
                Sistema de Gestão Académica
            </small>

        </div>

        <div class="card-body p-4">

            <?php if ($alerta): ?>

                <div class="alert alert-<?= e($alerta['tipo']) ?>">

                    <?= $alerta['mensagem'] ?>

                </div>

            <?php endif; ?>

            <form method="POST">

                <div class="mb-3">

                    <label class="form-label fw-semibold">

                        E-mail

                    </label>

                    <div class="input-group">

                        <span class="input-group-text">
                            <i class="fa-solid fa-envelope"></i>
                        </span>

                        <input
                            type="email"
                            name="email"
                            class="form-control"
                            placeholder="Digite o seu e-mail"
                            required>

                    </div>

                </div>


                <div class="mb-4">

                    <label class="form-label fw-semibold">

                        Palavra-passe

                    </label>

                    <div class="input-group">

                        <span class="input-group-text">
                            <i class="fa-solid fa-lock"></i>
                        </span>

                        <input
                            type="password"
                            name="senha"
                            class="form-control"
                            placeholder="Digite a sua palavra-passe"
                            required>

                    </div>

                </div>


                <button
                    type="submit"
                    name="btn_login"
                    class="btn btn-cacoin w-100 py-3 fw-bold">

                    <i class="fa-solid fa-right-to-bracket me-2"></i>

                    Entrar no Sistema

                </button>

            </form>

            <div class="text-center mt-4">

                <a
                    href="index.php?action=inicio"
                    class="text-muted text-decoration-none">

                    <i class="fa-solid fa-arrow-left me-1"></i>

                    Voltar ao início

                </a>

            </div>

        </div>

    </div>

</div>


<?php else: ?>

<!-- =========================================================
     SISTEMA INTERNO
========================================================= -->

<div class="app-wrapper">


<!-- SIDEBAR -->

<aside
    class="sidebar"
    id="sidebar">

    <div class="sidebar-brand">

        <a
            href="index.php?action=<?= isProfessor() ? 'prof_dashboard' : 'dashboard' ?>"
            class="text-decoration-none text-white">

            <div class="d-flex align-items-center">

                <i class="fa-solid fa-graduation-cap fa-2x text-warning me-2"></i>

                <div>

                    <div class="fw-bold fs-5">
                        CACOIN
                    </div>

                    <small class="text-white-50">
                        Centro de Formação
                    </small>

                </div>

            </div>

        </a>

    </div>


    <?php if (isProfessor()): ?>

        <!-- MENU PROFESSOR -->

        <div class="sidebar-section">
            Área do Professor
        </div>

        <a
            href="index.php?action=prof_dashboard"
            class="sidebar-link <?= $action === 'prof_dashboard' ? 'active' : '' ?>">

            <i class="fa-solid fa-chart-line"></i>

            Dashboard

        </a>

        <a
            href="index.php?action=prof_turmas"
            class="sidebar-link <?= in_array($action, ['prof_turmas','prof_turma']) ? 'active' : '' ?>">

            <i class="fa-solid fa-users-rectangle"></i>

            Minhas Turmas

        </a>

        <a
            href="index.php?action=prof_presencas"
            class="sidebar-link <?= $action === 'prof_presencas' ? 'active' : '' ?>">

            <i class="fa-solid fa-calendar-check"></i>

            Presenças

        </a>

        <a
            href="index.php?action=prof_notas"
            class="sidebar-link <?= $action === 'prof_notas' ? 'active' : '' ?>">

            <i class="fa-solid fa-file-pen"></i>

            Notas e Avaliações

        </a>


    <?php else: ?>

        <!-- MENU DIREÇÃO / SECRETARIA -->

        <div class="sidebar-section">
            Principal
        </div>

        <a
            href="index.php?action=dashboard"
            class="sidebar-link <?= $action === 'dashboard' ? 'active' : '' ?>">

            <i class="fa-solid fa-chart-line"></i>

            Visão Geral

        </a>


        <div class="sidebar-section">
            Gestão Académica
        </div>

        <a
            href="index.php?action=cursos"
            class="sidebar-link <?= $action === 'cursos' ? 'active' : '' ?>">

            <i class="fa-solid fa-book"></i>

            Cursos

        </a>

        <a
            href="index.php?action=turmas"
            class="sidebar-link <?= $action === 'turmas' ? 'active' : '' ?>">

            <i class="fa-solid fa-users-rectangle"></i>

            Turmas

        </a>

        <a
            href="index.php?action=salas"
            class="sidebar-link <?= $action === 'salas' ? 'active' : '' ?>">

            <i class="fa-solid fa-door-open"></i>

            Salas

        </a>

        <a
            href="index.php?action=alunos"
            class="sidebar-link <?= $action === 'alunos' ? 'active' : '' ?>">

            <i class="fa-solid fa-user-graduate"></i>

            Alunos

        </a>


        <div class="sidebar-section">
            Recursos Humanos
        </div>

        <a
            href="index.php?action=professores"
            class="sidebar-link <?= $action === 'professores' ? 'active' : '' ?>">

            <i class="fa-solid fa-chalkboard-user"></i>

            Professores

        </a>


        <div class="sidebar-section">
            Financeiro
        </div>

        <a
            href="index.php?action=pagamentos"
            class="sidebar-link <?= $action === 'pagamentos' ? 'active' : '' ?>">

            <i class="fa-solid fa-money-bill-wave"></i>

            Pagamentos

        </a>

    <?php endif; ?>


    <div class="profile-box mt-auto">

        <div class="small text-white-50">
            Utilizador conectado
        </div>

        <div class="fw-bold">
            <?= e($_SESSION['user_nome'] ?? '') ?>
        </div>

        <span class="badge bg-warning text-dark mt-1">

            <?= e($_SESSION['user_perfil'] ?? '') ?>

        </span>

        <a
            href="index.php?action=logout"
            class="btn btn-outline-danger btn-sm w-100 mt-3">

            <i class="fa-solid fa-right-from-bracket me-1"></i>

            Terminar Sessão

        </a>

    </div>

</aside>


<!-- CONTEÚDO -->

<main class="main-content">


    <!-- TOPBAR -->

    <div class="topbar">

        <div class="d-flex align-items-center justify-content-between">

            <div>

                <button
                    class="btn btn-light mobile-menu"
                    onclick="toggleSidebar()">

                    <i class="fa-solid fa-bars"></i>

                </button>

                <span class="ms-2 fw-semibold text-muted">

                    <?= isProfessor()
                        ? 'Área do Professor'
                        : 'Painel Administrativo'
                    ?>

                </span>

            </div>

            <div class="d-flex align-items-center gap-3">

                <span class="d-none d-md-inline text-muted small">

                    <?= date('d/m/Y') ?>

                </span>

                <div>

                    <i class="fa-solid fa-circle-user fa-2x text-secondary"></i>

                </div>

            </div>

        </div>

    </div>


    <div class="content-area">


        <?php if ($alerta): ?>

            <div
                class="alert alert-<?= e($alerta['tipo']) ?> alert-dismissible fade show">

                <?= $alerta['mensagem'] ?>

                <button
                    type="button"
                    class="btn-close"
                    data-bs-dismiss="alert">
                </button>

            </div>

        <?php endif; ?>


<!-- =========================================================
     DASHBOARD DIREÇÃO / SECRETARIA
========================================================= -->

<?php if ($action === 'dashboard' && isGestao()): ?>


<?php

$total_alunos = 0;
$total_professores = 0;
$total_cursos = 0;
$total_turmas = 0;
$total_salas = 0;
$total_pagamentos = 0;

try {
    $total_alunos =
        $pdo->query("SELECT COUNT(*) FROM alunos")->fetchColumn();
} catch (Exception $e) {}

try {
    $total_professores =
        $pdo->query("SELECT COUNT(*) FROM professores")->fetchColumn();
} catch (Exception $e) {}

try {
    $total_cursos =
        $pdo->query("SELECT COUNT(*) FROM cursos WHERE ativo = 1")->fetchColumn();
} catch (Exception $e) {}

try {
    $total_turmas =
        $pdo->query("SELECT COUNT(*) FROM turmas")->fetchColumn();
} catch (Exception $e) {}

try {
    $total_salas =
        $pdo->query("SELECT COUNT(*) FROM salas")->fetchColumn();
} catch (Exception $e) {}

try {
    $total_pagamentos =
        $pdo->query("SELECT COUNT(*) FROM pagamentos")->fetchColumn();
} catch (Exception $e) {}

?>


<div class="d-flex justify-content-between align-items-center mb-4">

    <div>

        <h2 class="page-title mb-1">
            Visão Geral
        </h2>

        <p class="text-muted mb-0">
            Bem-vindo ao painel de gestão do CACOIN.
        </p>

    </div>

</div>


<div class="row g-4 mb-4">

    <div class="col-sm-6 col-xl-3">

        <div class="stat-card">

            <div class="d-flex justify-content-between">

                <div>

                    <small class="text-muted">
                        Alunos
                    </small>

                    <h2 class="fw-bold mb-0">
                        <?= $total_alunos ?>
                    </h2>

                </div>

                <div class="stat-icon bg-primary-subtle text-primary">

                    <i class="fa-solid fa-user-graduate"></i>

                </div>

            </div>

        </div>

    </div>


    <div class="col-sm-6 col-xl-3">

        <div class="stat-card">

            <div class="d-flex justify-content-between">

                <div>

                    <small class="text-muted">
                        Professores
                    </small>

                    <h2 class="fw-bold mb-0">
                        <?= $total_professores ?>
                    </h2>

                </div>

                <div class="stat-icon bg-warning-subtle text-warning">

                    <i class="fa-solid fa-chalkboard-user"></i>

                </div>

            </div>

        </div>

    </div>


    <div class="col-sm-6 col-xl-3">

        <div class="stat-card">

            <div class="d-flex justify-content-between">

                <div>

                    <small class="text-muted">
                        Cursos Ativos
                    </small>

                    <h2 class="fw-bold mb-0">
                        <?= $total_cursos ?>
                    </h2>

                </div>

                <div class="stat-icon bg-success-subtle text-success">

                    <i class="fa-solid fa-book"></i>

                </div>

            </div>

        </div>

    </div>


    <div class="col-sm-6 col-xl-3">

        <div class="stat-card">

            <div class="d-flex justify-content-between">

                <div>

                    <small class="text-muted">
                        Turmas
                    </small>

                    <h2 class="fw-bold mb-0">
                        <?= $total_turmas ?>
                    </h2>

                </div>

                <div class="stat-icon bg-info-subtle text-info">

                    <i class="fa-solid fa-users-rectangle"></i>

                </div>

            </div>

        </div>

    </div>

</div>


<div class="row g-4">

    <div class="col-lg-8">

        <div class="table-card">

            <div class="p-4 border-bottom">

                <h5 class="fw-bold mb-1">
                    Estrutura Académica
                </h5>

                <small class="text-muted">
                    Resumo da estrutura atual do centro.
                </small>

            </div>

            <div class="table-responsive">

                <table class="table table-hover align-middle mb-0">

                    <tbody>

                        <tr>

                            <td>
                                <i class="fa-solid fa-book text-primary me-2"></i>
                                Cursos
                            </td>

                            <td class="text-end fw-bold">
                                <?= $total_cursos ?>
                            </td>

                        </tr>

                        <tr>

                            <td>
                                <i class="fa-solid fa-users text-success me-2"></i>
                                Turmas
                            </td>

                            <td class="text-end fw-bold">
                                <?= $total_turmas ?>
                            </td>

                        </tr>

                        <tr>

                            <td>
                                <i class="fa-solid fa-door-open text-warning me-2"></i>
                                Salas
                            </td>

                            <td class="text-end fw-bold">
                                <?= $total_salas ?>
                            </td>

                        </tr>

                        <tr>

                            <td>
                                <i class="fa-solid fa-user-graduate text-info me-2"></i>
                                Alunos
                            </td>

                            <td class="text-end fw-bold">
                                <?= $total_alunos ?>
                            </td>

                        </tr>

                    </tbody>

                </table>

            </div>

        </div>

    </div>


    <div class="col-lg-4">

        <div class="table-card p-4">

            <h5 class="fw-bold">
                Ações Rápidas
            </h5>

            <div class="d-grid gap-2 mt-3">

                <?php if (isDirecao()): ?>

                    <a
                        href="index.php?action=cursos"
                        class="btn btn-outline-primary">

                        <i class="fa-solid fa-plus me-2"></i>
                        Novo Curso

                    </a>

                    <a
                        href="index.php?action=turmas"
                        class="btn btn-outline-success">

                        <i class="fa-solid fa-users-rectangle me-2"></i>
                        Nova Turma

                    </a>

                    <a
                        href="index.php?action=salas"
                        class="btn btn-outline-warning">

                        <i class="fa-solid fa-door-open me-2"></i>
                        Nova Sala

                    </a>

                <?php endif; ?>

                <a
                    href="index.php?action=alunos"
                    class="btn btn-outline-secondary">

                    <i class="fa-solid fa-user-graduate me-2"></i>
                    Consultar Alunos

                </a>

            </div>

        </div>

    </div>

</div>


<!-- =========================================================
     CURSOS
========================================================= -->

<?php elseif ($action === 'cursos' && isGestao()): ?>


<div class="d-flex justify-content-between align-items-center mb-4">

    <div>

        <h2 class="page-title">
            Gestão de Cursos
        </h2>

        <p class="text-muted">
            Cadastre e acompanhe os cursos oferecidos pelo CACOIN.
        </p>

    </div>

</div>


<div class="row g-4">


<?php if (isDirecao()): ?>

<div class="col-lg-4">

    <div class="table-card">

        <div class="p-4 border-bottom">

            <h5 class="fw-bold mb-0">
                <i class="fa-solid fa-plus-circle text-warning me-2"></i>
                Novo Curso
            </h5>

        </div>

        <div class="p-4">

            <form method="POST">

                <div class="mb-3">

                    <label class="form-label fw-semibold">
                        Nome do Curso
                    </label>

                    <input
                        type="text"
                        name="nome"
                        class="form-control"
                        required>

                </div>


                <div class="mb-3">

                    <label class="form-label fw-semibold">
                        Código
                    </label>

                    <input
                        type="text"
                        name="codigo"
                        class="form-control"
                        placeholder="Ex: PW">

                </div>


                <div class="mb-3">

                    <label class="form-label fw-semibold">
                        Descrição
                    </label>

                    <textarea
                        name="descricao"
                        class="form-control"
                        rows="4"></textarea>

                </div>


                <div class="row g-2">

                    <div class="col-6">

                        <label class="form-label">
                            Preço (MT)
                        </label>

                        <input
                            type="number"
                            step="0.01"
                            name="preco"
                            class="form-control"
                            value="0">

                    </div>

                    <div class="col-6">

                        <label class="form-label">
                            Duração
                        </label>

                        <input
                            type="number"
                            name="duracao_meses"
                            class="form-control"
                            value="6">

                    </div>

                </div>


                <div class="mb-3 mt-3">

                    <label class="form-label">
                        Carga Horária
                    </label>

                    <input
                        type="number"
                        name="carga_horaria"
                        class="form-control"
                        value="120">

                </div>


                <button
                    type="submit"
                    name="btn_cadastrar_curso"
                    class="btn btn-cacoin w-100 fw-bold">

                    <i class="fa-solid fa-save me-2"></i>

                    Cadastrar Curso

                </button>

            </form>

        </div>

    </div>

</div>

<?php endif; ?>


<div class="<?= isDirecao() ? 'col-lg-8' : 'col-lg-12' ?>">

    <div class="table-card">

        <div class="p-4 border-bottom">

            <h5 class="fw-bold mb-0">
                Cursos Registados
            </h5>

        </div>

        <div class="table-responsive">

            <table class="table table-hover align-middle mb-0">

                <thead class="table-light">

                    <tr>

                        <th>Curso</th>
                        <th>Código</th>
                        <th>Preço</th>
                        <th>Duração</th>
                        <th>Estado</th>

                        <?php if (isDirecao()): ?>
                            <th>Ação</th>
                        <?php endif; ?>

                    </tr>

                </thead>

                <tbody>

                    <?php foreach ($lista_cursos as $curso): ?>

                        <tr>

                            <td>

                                <div class="fw-bold">
                                    <?= e($curso['nome']) ?>
                                </div>

                                <small class="text-muted">
                                    <?= e($curso['descricao'] ?? '') ?>
                                </small>

                            </td>

                            <td>
                                <?= e($curso['codigo'] ?? '-') ?>
                            </td>

                            <td>
                                <?= number_format(
                                    $curso['preco'] ?? 0,
                                    2
                                ) ?> MT
                            </td>

                            <td>
                                <?= e($curso['duracao_meses'] ?? '-') ?>
                                meses
                            </td>

                            <td>

                                <?php if (
                                    !isset($curso['ativo'])
                                    || $curso['ativo'] == 1
                                ): ?>

                                    <span class="badge bg-success">
                                        Ativo
                                    </span>

                                <?php else: ?>

                                    <span class="badge bg-secondary">
                                        Inativo
                                    </span>

                                <?php endif; ?>

                            </td>

                            <?php if (isDirecao()): ?>

                            <td>

                                <form method="POST">

                                    <input
                                        type="hidden"
                                        name="curso_id"
                                        value="<?= $curso['id'] ?>">

                                    <button
                                        type="submit"
                                        name="btn_estado_curso"
                                        class="btn btn-sm btn-outline-secondary">

                                        <i class="fa-solid fa-power-off"></i>

                                    </button>

                                </form>

                            </td>

                            <?php endif; ?>

                        </tr>

                    <?php endforeach; ?>

                </tbody>

            </table>

        </div>

    </div>

</div>

</div>


<!-- =========================================================
     TURMAS
========================================================= -->

<?php elseif ($action === 'turmas' && isGestao()): ?>


<div class="d-flex justify-content-between align-items-center mb-4">

    <div>

        <h2 class="page-title">
            Gestão de Turmas
        </h2>

        <p class="text-muted">
            Crie turmas, associe salas e atribua professores.
        </p>

    </div>

</div>


<?php if (isDirecao()): ?>

<div class="table-card p-4 mb-4">

    <h5 class="fw-bold mb-3">

        <i class="fa-solid fa-plus-circle text-warning me-2"></i>

        Criar Nova Turma

    </h5>

    <form method="POST">

        <div class="row g-3">

            <div class="col-md-4">

                <label class="form-label fw-semibold">
                    Curso
                </label>

                <select
                    name="curso_id"
                    class="form-select"
                    required>

                    <option value="">
                        Selecionar curso
                    </option>

                    <?php foreach ($lista_cursos as $curso): ?>

                        <?php if (
                            !isset($curso['ativo'])
                            || $curso['ativo'] == 1
                        ): ?>

                            <option value="<?= $curso['id'] ?>">

                                <?= e($curso['nome']) ?>

                            </option>

                        <?php endif; ?>

                    <?php endforeach; ?>

                </select>

            </div>


            <div class="col-md-4">

                <label class="form-label fw-semibold">
                    Nome da Turma
                </label>

                <input
                    type="text"
                    name="nome"
                    class="form-control"
                    placeholder="Ex: Programação Web - Turma A"
                    required>

            </div>


            <div class="col-md-4">

                <label class="form-label fw-semibold">
                    Sala
                </label>

                <select
                    name="sala_id"
                    class="form-select">

                    <option value="">
                        Sem sala definida
                    </option>

                    <?php foreach ($lista_salas as $sala): ?>

                        <option value="<?= $sala['id'] ?>">

                            <?= e($sala['nome']) ?>

                        </option>

                    <?php endforeach; ?>

                </select>

            </div>


            <div class="col-md-3">

                <label class="form-label">
                    Turno
                </label>

                <select
                    name="turno"
                    class="form-select">

                    <option value="">
                        Selecionar
                    </option>

                    <option value="Manhã">
                        Manhã
                    </option>

                    <option value="Tarde">
                        Tarde
                    </option>

                    <option value="Noite">
                        Noite
                    </option>

                </select>

            </div>


            <div class="col-md-3">

                <label class="form-label">
                    Horário
                </label>

                <input
                    type="text"
                    name="horario"
                    class="form-control"
                    placeholder="08:00 - 10:00">

            </div>


            <div class="col-md-3">

                <label class="form-label">
                    Data de Início
                </label>

                <input
                    type="date"
                    name="data_inicio"
                    class="form-control">

            </div>


            <div class="col-md-3">

                <label class="form-label">
                    Data de Fim
                </label>

                <input
                    type="date"
                    name="data_fim"
                    class="form-control">

            </div>

        </div>


        <button
            type="submit"
            name="btn_cadastrar_turma"
            class="btn btn-cacoin mt-4 fw-bold">

            <i class="fa-solid fa-plus me-2"></i>

            Criar Turma

        </button>

    </form>

</div>

<?php endif; ?>


<div class="table-card">

    <div class="p-4 border-bottom">

        <h5 class="fw-bold mb-0">
            Turmas Registadas
        </h5>

    </div>

    <div class="table-responsive">

        <table class="table table-hover align-middle mb-0">

            <thead class="table-light">

                <tr>

                    <th>Turma</th>
                    <th>Curso</th>
                    <th>Sala</th>
                    <th>Horário</th>
                    <th>Estado</th>

                    <?php if (isDirecao()): ?>
                        <th>Professor</th>
                    <?php endif; ?>

                </tr>

            </thead>

            <tbody>

            <?php foreach ($lista_turmas as $turma): ?>

                <tr>

                    <td>

                        <strong>
                            <?= e($turma['nome']) ?>
                        </strong>

                        <br>

                        <small class="text-muted">

                            <?= e($turma['turno'] ?? '') ?>

                        </small>

                    </td>

                    <td>
                        <?= e($turma['curso_nome'] ?? '-') ?>
                    </td>

                    <td>
                        <?= e($turma['sala_nome'] ?? 'Não definida') ?>
                    </td>

                    <td>
                        <?= e($turma['horario'] ?? '-') ?>
                    </td>

                    <td>

                        <span class="badge bg-success">

                            <?= e($turma['estado'] ?? 'Ativa') ?>

                        </span>

                    </td>


                    <?php if (isDirecao()): ?>

                    <td>

                        <form
                            method="POST"
                            class="d-flex gap-2">

                            <input
                                type="hidden"
                                name="turma_id"
                                value="<?= $turma['id'] ?>">

                            <select
                                name="professor_id"
                                class="form-select form-select-sm">

                                <option value="">
                                    Selecionar professor
                                </option>

                                <?php foreach (
                                    $lista_professores
                                    as $prof
                                ): ?>

                                    <option
                                        value="<?= $prof['id'] ?>">

                                        <?= e($prof['nome']) ?>

                                    </option>

                                <?php endforeach; ?>

                            </select>

                            <button
                                type="submit"
                                name="btn_atribuir_professor_turma"
                                class="btn btn-sm btn-primary">

                                <i class="fa-solid fa-user-plus"></i>

                            </button>

                        </form>

                    </td>

                    <?php endif; ?>

                </tr>

            <?php endforeach; ?>

            </tbody>

        </table>

    </div>

</div>


<!-- =========================================================
     SALAS
========================================================= -->

<?php elseif ($action === 'salas' && isDirecao()): ?>


<div class="d-flex justify-content-between align-items-center mb-4">

    <div>

        <h2 class="page-title">
            Gestão de Salas
        </h2>

        <p class="text-muted">
            Gerencie as salas utilizadas pelas turmas.
        </p>

    </div>

</div>


<div class="row g-4">

    <div class="col-lg-4">

        <div class="table-card p-4">

            <h5 class="fw-bold mb-3">
                Nova Sala
            </h5>

            <form method="POST">

                <div class="mb-3">

                    <label class="form-label">
                        Nome da Sala
                    </label>

                    <input
                        type="text"
                        name="nome"
                        class="form-control"
                        placeholder="Ex: Sala 01"
                        required>

                </div>


                <div class="mb-3">

                    <label class="form-label">
                        Localização
                    </label>

                    <input
                        type="text"
                        name="localizacao"
                        class="form-control"
                        placeholder="Bloco A">

                </div>


                <div class="mb-3">

                    <label class="form-label">
                        Capacidade
                    </label>

                    <input
                        type="number"
                        name="capacidade"
                        class="form-control"
                        min="1">

                </div>


                <button
                    type="submit"
                    name="btn_cadastrar_sala"
                    class="btn btn-cacoin w-100">

                    <i class="fa-solid fa-save me-2"></i>

                    Guardar Sala

                </button>

            </form>

        </div>

    </div>


    <div class="col-lg-8">

        <div class="table-card">

            <div class="p-4 border-bottom">

                <h5 class="fw-bold mb-0">
                    Salas Disponíveis
                </h5>

            </div>

            <div class="table-responsive">

                <table class="table table-hover mb-0">

                    <thead class="table-light">

                        <tr>
                            <th>Sala</th>
                            <th>Localização</th>
                            <th>Capacidade</th>
                            <th>Estado</th>
                        </tr>

                    </thead>

                    <tbody>

                        <?php foreach ($lista_salas as $sala): ?>

                            <tr>

                                <td class="fw-bold">
                                    <?= e($sala['nome']) ?>
                                </td>

                                <td>
                                    <?= e($sala['localizacao'] ?? '-') ?>
                                </td>

                                <td>
                                    <?= e($sala['capacidade'] ?? '-') ?>
                                    lugares
                                </td>

                                <td>

                                    <span class="badge bg-success">

                                        <?= e(
                                            $sala['estado']
                                            ?? 'Disponível'
                                        ) ?>

                                    </span>

                                </td>

                            </tr>

                        <?php endforeach; ?>

                    </tbody>

                </table>

            </div>

        </div>

    </div>

</div>


<!-- =========================================================
     PROFESSORES
========================================================= -->

<?php elseif ($action === 'professores' && isGestao()): ?>


<div class="d-flex justify-content-between align-items-center mb-4">

    <div>

        <h2 class="page-title">
            Gestão de Professores
        </h2>

        <p class="text-muted">
            Cadastre professores e associe-os aos cursos.
        </p>

    </div>

</div>


<div class="row g-4">


<?php if (isGestao()): ?>

<div class="col-lg-5">

    <div class="table-card">

        <div class="p-4 border-bottom">

            <h5 class="fw-bold">
                <i class="fa-solid fa-user-plus text-warning me-2"></i>

                Novo Professor

            </h5>

        </div>

        <div class="p-4">

            <form method="POST">

                <div class="mb-3">

                    <label class="form-label">
                        Nome Completo
                    </label>

                    <input
                        type="text"
                        name="nome"
                        class="form-control"
                        required>

                </div>


                <div class="row g-2">

                    <div class="col-6">

                        <label class="form-label">
                            BI
                        </label>

                        <input
                            type="text"
                            name="bi"
                            class="form-control">

                    </div>

                    <div class="col-6">

                        <label class="form-label">
                            Telefone
                        </label>

                        <input
                            type="text"
                            name="telefone"
                            class="form-control">

                    </div>

                </div>


                <div class="mb-3 mt-3">

                    <label class="form-label">
                        E-mail
                    </label>

                    <input
                        type="email"
                        name="email"
                        class="form-control"
                        required>

                </div>


                <div class="mb-3">

                    <label class="form-label">
                        Palavra-passe
                    </label>

                    <input
                        type="password"
                        name="senha"
                        class="form-control"
                        value="123456">

                    <small class="text-muted">
                        Palavra-passe inicial: 123456
                    </small>

                </div>


                <label class="form-label fw-semibold">
                    Cursos que poderá lecionar
                </label>

                <div
                    class="border rounded p-3 mb-3"
                    style="max-height:180px;overflow:auto;">

                    <?php foreach ($lista_cursos as $curso): ?>

                        <div class="form-check">

                            <input
                                class="form-check-input"
                                type="checkbox"
                                name="cursos[]"
                                value="<?= $curso['id'] ?>"
                                id="cursoProf<?= $curso['id'] ?>">

                            <label
                                class="form-check-label"
                                for="cursoProf<?= $curso['id'] ?>">

                                <?= e($curso['nome']) ?>

                            </label>

                        </div>

                    <?php endforeach; ?>

                </div>


                <button
                    type="submit"
                    name="btn_cadastrar_professor"
                    class="btn btn-cacoin w-100 fw-bold">

                    <i class="fa-solid fa-save me-2"></i>

                    Cadastrar Professor

                </button>

            </form>

        </div>

    </div>

</div>

<?php endif; ?>


<div class="col-lg-7">

    <div class="table-card">

        <div class="p-4 border-bottom">

            <h5 class="fw-bold">
                Corpo Docente
            </h5>

        </div>

        <div class="table-responsive">

            <table class="table table-hover align-middle mb-0">

                <thead class="table-light">

                    <tr>

                        <th>Professor</th>
                        <th>Contacto</th>
                        <th>Cursos</th>
                        <th>Estado</th>

                    </tr>

                </thead>

                <tbody>

                    <?php foreach ($lista_professores as $prof): ?>

                        <tr>

                            <td>

                                <div class="fw-bold">
                                    <?= e($prof['nome']) ?>
                                </div>

                                <small class="text-muted">
                                    <?= e($prof['email']) ?>
                                </small>

                            </td>

                            <td>
                                <?= e($prof['telefone'] ?? '-') ?>
                            </td>

                            <td>

                                <small>
                                    <?= e(
                                        $prof['cursos_nomes']
                                        ?? 'Nenhum'
                                    ) ?>
                                </small>

                            </td>

                            <td>

                                <span class="badge bg-success">

                                    <?= e(
                                        $prof['estado']
                                        ?? 'Ativo'
                                    ) ?>

                                </span>

                            </td>

                        </tr>

                    <?php endforeach; ?>

                </tbody>

            </table>

        </div>

    </div>

</div>

</div>


<!-- =========================================================
     ALUNOS
========================================================= -->

<?php elseif ($action === 'alunos' && isGestao()): ?>


<div class="d-flex justify-content-between align-items-center mb-4">

    <div>

        <h2 class="page-title">
            Gestão de Alunos
        </h2>

        <p class="text-muted">
            Consulte os alunos matriculados no centro.
        </p>

    </div>

</div>


<div class="table-card">

    <div class="table-responsive">

        <table class="table table-hover align-middle mb-0">

            <thead class="table-light">

                <tr>

                    <th>#</th>
                    <th>Aluno</th>
                    <th>BI</th>
                    <th>Curso</th>
                    <th>Contacto</th>
                    <th>Estado</th>

                </tr>

            </thead>

            <tbody>

            <?php

            $alunos_lista = [];

            try {

                $alunos_lista = $pdo->query("
                    SELECT
                        a.*,
                        c.nome AS curso_nome
                    FROM alunos a
                    LEFT JOIN cursos c
                        ON a.curso_id = c.id
                    ORDER BY a.id DESC
                ")->fetchAll();

            } catch (Exception $e) {}

            ?>


            <?php foreach ($alunos_lista as $aluno): ?>

                <tr>

                    <td>
                        <?= e($aluno['id']) ?>
                    </td>

                    <td>

                        <div class="fw-bold">
                            <?= e($aluno['nome']) ?>
                        </div>

                    </td>

                    <td>
                        <?= e($aluno['bi'] ?? '-') ?>
                    </td>

                    <td>

                        <span class="badge bg-primary">

                            <?= e(
                                $aluno['curso_nome']
                                ?? 'Sem curso'
                            ) ?>

                        </span>

                    </td>

                    <td>
                        <?= e($aluno['telefone'] ?? '-') ?>
                    </td>

                    <td>

                        <span class="badge bg-success">
                            Ativo
                        </span>

                    </td>

                </tr>

            <?php endforeach; ?>

            </tbody>

        </table>

    </div>

</div>


<!-- =========================================================
     PAGAMENTOS
========================================================= -->

<?php elseif ($action === 'pagamentos' && isGestao()): ?>


<div class="d-flex justify-content-between align-items-center mb-4">

    <div>

        <h2 class="page-title">
            Gestão de Pagamentos
        </h2>

        <p class="text-muted">
            Consulte os pagamentos realizados pelos alunos.
        </p>

    </div>

</div>


<div class="table-card">

    <div class="table-responsive">

        <table class="table table-hover align-middle mb-0">

            <thead class="table-light">

                <tr>

                    <th>Aluno</th>
                    <th>Valor</th>
                    <th>Data</th>
                    <th>Método</th>
                    <th>Estado</th>

                </tr>

            </thead>

            <tbody>

            <?php

            $pagamentos = [];

            try {

                $pagamentos = $pdo->query("
                    SELECT
                        p.*,
                        a.nome AS aluno_nome
                    FROM pagamentos p
                    LEFT JOIN alunos a
                        ON p.aluno_id = a.id
                    ORDER BY p.id DESC
                ")->fetchAll();

            } catch (Exception $e) {}

            ?>


            <?php foreach ($pagamentos as $pagamento): ?>

                <tr>

                    <td class="fw-bold">

                        <?= e(
                            $pagamento['aluno_nome']
                            ?? 'N/A'
                        ) ?>

                    </td>

                    <td>

                        <strong>

                            <?= number_format(
                                $pagamento['valor'] ?? 0,
                                2
                            ) ?>

                            MT

                        </strong>

                    </td>

                    <td>

                        <?= e(
                            $pagamento['data_pagamento']
                            ?? '-'
                        ) ?>

                    </td>

                    <td>

                        <?= e(
                            $pagamento['metodo_pagamento']
                            ??
                            $pagamento['metodo']
                            ??
                            '-'
                        ) ?>

                    </td>

                    <td>

                        <span class="badge bg-success">

                            <?= e(
                                $pagamento['estado']
                                ?? 'Confirmado'
                            ) ?>

                        </span>

                    </td>

                </tr>

            <?php endforeach; ?>

            </tbody>

        </table>

    </div>

</div>


<!-- =========================================================
     DASHBOARD PROFESSOR
========================================================= -->

<?php elseif ($action === 'prof_dashboard' && isProfessor()): ?>


<?php

$prof_id = $_SESSION['user_id'];

$minhasTurmas = [];

try {

    $stmt = $pdo->prepare("
        SELECT
            t.*,
            c.nome AS curso_nome,
            s.nome AS sala_nome
        FROM professor_turmas pt
        INNER JOIN turmas t
            ON pt.turma_id = t.id
        LEFT JOIN cursos c
            ON t.curso_id = c.id
        LEFT JOIN salas s
            ON t.sala_id = s.id
        WHERE pt.professor_id = ?
        ORDER BY t.id DESC
    ");

    $stmt->execute([$prof_id]);

    $minhasTurmas = $stmt->fetchAll();

} catch (Exception $e) {}

$totalMinhasTurmas = count($minhasTurmas);

$totalMeusAlunos = 0;

try {

    $stmt = $pdo->prepare("
        SELECT COUNT(DISTINCT a.id)
        FROM alunos a
        INNER JOIN turmas t
            ON a.turma_id = t.id
        INNER JOIN professor_turmas pt
            ON t.id = pt.turma_id
        WHERE pt.professor_id = ?
    ");

    $stmt->execute([$prof_id]);

    $totalMeusAlunos = $stmt->fetchColumn() ?? 0;

} catch (Exception $e) {}

?>


<div class="mb-4">

    <h2 class="page-title">
        Olá, <?= e($_SESSION['user_nome']) ?>
    </h2>

    <p class="text-muted">
        Aqui está o resumo das suas atividades como professor.
    </p>

</div>


<div class="row g-4 mb-4">

    <div class="col-md-6 col-xl-4">

        <div class="stat-card">

            <div class="d-flex justify-content-between">

                <div>

                    <small class="text-muted">
                        Minhas Turmas
                    </small>

                    <h2 class="fw-bold">
                        <?= $totalMinhasTurmas ?>
                    </h2>

                </div>

                <div class="stat-icon bg-primary-subtle text-primary">

                    <i class="fa-solid fa-users-rectangle"></i>

                </div>

            </div>

        </div>

    </div>


    <div class="col-md-6 col-xl-4">

        <div class="stat-card">

            <div class="d-flex justify-content-between">

                <div>

                    <small class="text-muted">
                        Meus Alunos
                    </small>

                    <h2 class="fw-bold">
                        <?= $totalMeusAlunos ?>
                    </h2>

                </div>

                <div class="stat-icon bg-success-subtle text-success">

                    <i class="fa-solid fa-user-graduate"></i>

                </div>

            </div>

        </div>

    </div>


    <div class="col-md-6 col-xl-4">

        <div class="stat-card">

            <div class="d-flex justify-content-between">

                <div>

                    <small class="text-muted">
                        Data
                    </small>

                    <h5 class="fw-bold mt-2">
                        <?= date('d/m/Y') ?>
                    </h5>

                </div>

                <div class="stat-icon bg-warning-subtle text-warning">

                    <i class="fa-solid fa-calendar-day"></i>

                </div>

            </div>

        </div>

    </div>

</div>


<div class="table-card">

    <div class="p-4 border-bottom">

        <h5 class="fw-bold mb-1">
            Minhas Turmas
        </h5>

        <small class="text-muted">
            Selecione uma turma para gerir alunos,
            presença e avaliações.
        </small>

    </div>

    <div class="table-responsive">

        <table class="table table-hover align-middle mb-0">

            <thead class="table-light">

                <tr>

                    <th>Turma</th>
                    <th>Curso</th>
                    <th>Sala</th>
                    <th>Horário</th>
                    <th>Ação</th>

                </tr>

            </thead>

            <tbody>

                <?php foreach ($minhasTurmas as $turma): ?>

                    <tr>

                        <td class="fw-bold">

                            <?= e($turma['nome']) ?>

                        </td>

                        <td>

                            <?= e(
                                $turma['curso_nome']
                                ?? '-'
                            ) ?>

                        </td>

                        <td>

                            <?= e(
                                $turma['sala_nome']
                                ?? 'Não definida'
                            ) ?>

                        </td>

                        <td>

                            <?= e(
                                $turma['horario']
                                ?? '-'
                            ) ?>

                        </td>

                        <td>

                            <a
                                href="index.php?action=prof_turma&turma_id=<?= $turma['id'] ?>"
                                class="btn btn-sm btn-cacoin">

                                <i class="fa-solid fa-arrow-right me-1"></i>

                                Abrir Turma

                            </a>

                        </td>

                    </tr>

                <?php endforeach; ?>


                <?php if (empty($minhasTurmas)): ?>

                    <tr>

                        <td
                            colspan="5"
                            class="text-center text-muted py-5">

                            <i class="fa-solid fa-users-slash fa-2x mb-3"></i>

                            <br>

                            Nenhuma turma foi atribuída à sua conta.

                        </td>

                    </tr>

                <?php endif; ?>

            </tbody>

        </table>

    </div>

</div>


<!-- =========================================================
     TURMAS PROFESSOR
========================================================= -->

<?php elseif ($action === 'prof_turmas' && isProfessor()): ?>


<?php

$stmt = $pdo->prepare("
    SELECT
        t.*,
        c.nome AS curso_nome,
        s.nome AS sala_nome
    FROM professor_turmas pt
    INNER JOIN turmas t
        ON pt.turma_id = t.id
    LEFT JOIN cursos c
        ON t.curso_id = c.id
    LEFT JOIN salas s
        ON t.sala_id = s.id
    WHERE pt.professor_id = ?
    ORDER BY t.id DESC
");

$stmt->execute([
    $_SESSION['user_id']
]);

$turmasProfessor = $stmt->fetchAll();

?>


<div class="mb-4">

    <h2 class="page-title">
        Minhas Turmas
    </h2>

    <p class="text-muted">
        Aceda aos alunos, presenças e avaliações de cada turma.
    </p>

</div>


<div class="row g-4">

<?php foreach ($turmasProfessor as $turma): ?>

    <div class="col-md-6 col-xl-4">

        <div class="card card-modern h-100">

            <div class="card-body p-4">

                <span class="badge bg-primary mb-3">

                    <?= e(
                        $turma['curso_nome']
                        ?? 'Curso'
                    ) ?>

                </span>

                <h5 class="fw-bold">

                    <?= e($turma['nome']) ?>

                </h5>

                <div class="text-muted small mt-3">

                    <div class="mb-2">

                        <i class="fa-solid fa-door-open me-2"></i>

                        <?= e(
                            $turma['sala_nome']
                            ?? 'Sala não definida'
                        ) ?>

                    </div>

                    <div class="mb-2">

                        <i class="fa-solid fa-clock me-2"></i>

                        <?= e(
                            $turma['horario']
                            ?? 'Horário não definido'
                        ) ?>

                    </div>

                    <div>

                        <i class="fa-solid fa-calendar me-2"></i>

                        <?= e(
                            $turma['turno']
                            ?? 'Turno não definido'
                        ) ?>

                    </div>

                </div>


                <a
                    href="index.php?action=prof_turma&turma_id=<?= $turma['id'] ?>"
                    class="btn btn-cacoin w-100 mt-4">

                    <i class="fa-solid fa-users me-2"></i>

                    Gerir Turma

                </a>

            </div>

        </div>

    </div>

<?php endforeach; ?>


<?php if (empty($turmasProfessor)): ?>

    <div class="col-12">

        <div class="alert alert-warning">

            Ainda não existem turmas atribuídas à sua conta.

        </div>

    </div>

<?php endif; ?>

</div>


<!-- =========================================================
     TURMA DO PROFESSOR
========================================================= -->

<?php elseif ($action === 'prof_turma' && isProfessor()): ?>


<?php

$turma_id = intval($_GET['turma_id'] ?? 0);

$stmt = $pdo->prepare("
    SELECT
        t.*,
        c.nome AS curso_nome,
        s.nome AS sala_nome
    FROM turmas t
    LEFT JOIN cursos c
        ON t.curso_id = c.id
    LEFT JOIN salas s
        ON t.sala_id = s.id
    INNER JOIN professor_turmas pt
        ON t.id = pt.turma_id
    WHERE t.id = ?
    AND pt.professor_id = ?
    LIMIT 1
");

$stmt->execute([
    $turma_id,
    $_SESSION['user_id']
]);

$turma = $stmt->fetch();

if (!$turma) {

    flash(
        'danger',
        'Turma não encontrada ou sem permissão.'
    );

    redirect('prof_turmas');
}


$stmt = $pdo->prepare("
    SELECT
        a.*,
        n.nota_teste1,
        n.nota_teste2,
        n.nota_exame,
        n.media_final,
        n.resultado
    FROM alunos a
    LEFT JOIN notas n
        ON a.id = n.aluno_id
    WHERE a.turma_id = ?
    ORDER BY a.nome ASC
");

$stmt->execute([
    $turma_id
]);

$alunosTurma = $stmt->fetchAll();


$aba = $_GET['aba'] ?? 'alunos';

?>


<div class="d-flex justify-content-between align-items-center mb-4">

    <div>

        <h2 class="page-title mb-1">

            <?= e($turma['nome']) ?>

        </h2>

        <p class="text-muted mb-0">

            <?= e(
                $turma['curso_nome']
                ?? ''
            ) ?>

            •
            <?= e(
                $turma['sala_nome']
                ?? 'Sala não definida'
            ) ?>

            •
            <?= e(
                $turma['horario']
                ?? ''
            ) ?>

        </p>

    </div>

    <a
        href="index.php?action=prof_turmas"
        class="btn btn-outline-secondary">

        <i class="fa-solid fa-arrow-left me-1"></i>

        Voltar

    </a>

</div>


<!-- ABAS -->

<ul class="nav nav-pills mb-4">

    <li class="nav-item">

        <a
            class="nav-link <?= $aba === 'alunos' ? 'active' : '' ?>"
            href="index.php?action=prof_turma&turma_id=<?= $turma_id ?>&aba=alunos">

            <i class="fa-solid fa-users me-1"></i>

            Alunos

        </a>

    </li>

    <li class="nav-item">

        <a
            class="nav-link <?= $aba === 'presenca' ? 'active' : '' ?>"
            href="index.php?action=prof_turma&turma_id=<?= $turma_id ?>&aba=presenca">

            <i class="fa-solid fa-calendar-check me-1"></i>

            Presença

        </a>

    </li>

    <li class="nav-item">

        <a
            class="nav-link <?= $aba === 'notas' ? 'active' : '' ?>"
            href="index.php?action=prof_turma&turma_id=<?= $turma_id ?>&aba=notas">

            <i class="fa-solid fa-file-pen me-1"></i>

            Notas

        </a>

    </li>

</ul>


<?php if ($aba === 'alunos'): ?>


<!-- LISTA DE ALUNOS -->

<div class="table-card">

    <div class="p-4 border-bottom">

        <h5 class="fw-bold mb-1">
            Lista de Alunos
        </h5>

        <small class="text-muted">

            Total:
            <?= count($alunosTurma) ?>
            aluno(s)

        </small>

    </div>

    <div class="table-responsive">

        <table class="table table-hover align-middle mb-0">

            <thead class="table-light">

                <tr>

                    <th>#</th>
                    <th>Aluno</th>
                    <th>BI</th>
                    <th>Contacto</th>
                    <th>Estado</th>

                </tr>

            </thead>

            <tbody>

                <?php $numero = 1; ?>

                <?php foreach ($alunosTurma as $aluno): ?>

                    <tr>

                        <td>
                            <?= $numero++ ?>
                        </td>

                        <td class="fw-bold">

                            <?= e($aluno['nome']) ?>

                        </td>

                        <td>

                            <?= e(
                                $aluno['bi']
                                ?? '-'
                            ) ?>

                        </td>

                        <td>

                            <?= e(
                                $aluno['telefone']
                                ?? '-'
                            ) ?>

                        </td>

                        <td>

                            <span class="badge bg-success">
                                Matriculado
                            </span>

                        </td>

                    </tr>

                <?php endforeach; ?>


                <?php if (empty($alunosTurma)): ?>

                    <tr>

                        <td
                            colspan="5"
                            class="text-center py-5 text-muted">

                            Nenhum aluno nesta turma.

                        </td>

                    </tr>

                <?php endif; ?>

            </tbody>

        </table>

    </div>

</div>


<?php elseif ($aba === 'presenca'): ?>


<!-- =========================================================
     LISTA DE PRESENÇA
========================================================= -->

<div class="table-card">

    <div class="p-4 border-bottom">

        <h5 class="fw-bold mb-1">

            <i class="fa-solid fa-calendar-check text-success me-2"></i>

            Lista de Presença

        </h5>

        <small class="text-muted">

            Marque Presente, Ausente ou Justificado para cada aluno.

        </small>

    </div>


    <form method="POST">

        <div class="p-4 border-bottom">

            <div class="row align-items-end">

                <div class="col-md-4">

                    <label class="form-label fw-semibold">

                        Data da Aula

                    </label>

                    <input
                        type="date"
                        name="data_presenca"
                        class="form-control"
                        value="<?= e(
                            $_GET['data']
                            ?? date('Y-m-d')
                        ) ?>"
                        required>

                </div>

            </div>

        </div>


        <div class="table-responsive">

            <table class="table align-middle mb-0">

                <thead class="table-light">

                    <tr>

                        <th>Aluno</th>
                        <th>Presença</th>
                        <th>Observação</th>

                    </tr>

                </thead>

                <tbody>

                <?php foreach ($alunosTurma as $aluno): ?>

                    <tr>

                        <td class="fw-bold">

                            <?= e($aluno['nome']) ?>

                        </td>

                        <td style="min-width:260px;">

                            <select
                                name="presenca[<?= $aluno['id'] ?>]"
                                class="form-select">

                                <option value="Presente">
                                    Presente
                                </option>

                                <option value="Ausente">
                                    Ausente
                                </option>

                                <option value="Justificado">
                                    Justificado
                                </option>

                            </select>

                        </td>

                        <td>

                            <input
                                type="text"
                                name="observacao[<?= $aluno['id'] ?>]"
                                class="form-control"
                                placeholder="Opcional">

                        </td>

                    </tr>

                <?php endforeach; ?>

                </tbody>

            </table>

        </div>


        <div class="p-4">

            <input
                type="hidden"
                name="turma_id"
                value="<?= $turma_id ?>">

            <button
                type="submit"
                name="btn_salvar_presenca"
                class="btn btn-success fw-bold">

                <i class="fa-solid fa-save me-2"></i>

                Guardar Lista de Presença

            </button>

        </div>

    </form>

</div>


<?php elseif ($aba === 'notas'): ?>


<!-- =========================================================
     NOTAS
========================================================= -->

<div class="table-card">

    <div class="p-4 border-bottom">

        <h5 class="fw-bold">
            <i class="fa-solid fa-file-pen text-primary me-2"></i>

            Pauta de Avaliações
        </h5>

    </div>

    <div class="table-responsive">

        <table class="table table-hover align-middle mb-0">

            <thead class="table-light">

                <tr>

                    <th>Aluno</th>
                    <th>T1</th>
                    <th>T2</th>
                    <th>Exame</th>
                    <th>Média</th>
                    <th>Resultado</th>
                    <th>Ação</th>

                </tr>

            </thead>

            <tbody>

            <?php foreach ($alunosTurma as $aluno): ?>

                <tr>

                    <td class="fw-bold">

                        <?= e($aluno['nome']) ?>

                    </td>

                    <td>
                        <?= $aluno['nota_teste1'] ?? '-' ?>
                    </td>

                    <td>
                        <?= $aluno['nota_teste2'] ?? '-' ?>
                    </td>

                    <td>
                        <?= $aluno['nota_exame'] ?? '-' ?>
                    </td>

                    <td class="fw-bold">

                        <?php if (
                            $aluno['media_final'] !== null
                        ): ?>

                            <?= number_format(
                                $aluno['media_final'],
                                2
                            ) ?>

                        <?php else: ?>

                            -

                        <?php endif; ?>

                    </td>

                    <td>

                        <?php if (
                            ($aluno['resultado'] ?? '')
                            === 'Aprovado'
                        ): ?>

                            <span class="badge bg-success">
                                Aprovado
                            </span>

                        <?php elseif (
                            ($aluno['resultado'] ?? '')
                            === 'Reprovado'
                        ): ?>

                            <span class="badge bg-danger">
                                Reprovado
                            </span>

                        <?php else: ?>

                            <span class="badge bg-secondary">
                                Pendente
                            </span>

                        <?php endif; ?>

                    </td>

                    <td>

                        <button
                            type="button"
                            class="btn btn-sm btn-cacoin"
                            data-bs-toggle="modal"
                            data-bs-target="#modalNota<?= $aluno['id'] ?>">

                            <i class="fa-solid fa-pen me-1"></i>

                            Lançar

                        </button>


                        <!-- MODAL NOTA -->

                        <div
                            class="modal fade"
                            id="modalNota<?= $aluno['id'] ?>"
                            tabindex="-1">

                            <div class="modal-dialog">

                                <div class="modal-content">

                                    <form method="POST">

                                        <div class="modal-header">

                                            <h5 class="modal-title">

                                                Notas de
                                                <?= e($aluno['nome']) ?>

                                            </h5>

                                            <button
                                                type="button"
                                                class="btn-close"
                                                data-bs-dismiss="modal">
                                            </button>

                                        </div>


                                        <div class="modal-body">

                                            <input
                                                type="hidden"
                                                name="aluno_id"
                                                value="<?= $aluno['id'] ?>">

                                            <input
                                                type="hidden"
                                                name="turma_id"
                                                value="<?= $turma_id ?>">


                                            <div class="mb-3">

                                                <label class="form-label">
                                                    Teste 1
                                                </label>

                                                <input
                                                    type="number"
                                                    step="0.1"
                                                    min="0"
                                                    max="20"
                                                    name="teste1"
                                                    class="form-control"
                                                    value="<?= e(
                                                        $aluno['nota_teste1']
                                                        ?? ''
                                                    ) ?>"
                                                    required>

                                            </div>


                                            <div class="mb-3">

                                                <label class="form-label">
                                                    Teste 2
                                                </label>

                                                <input
                                                    type="number"
                                                    step="0.1"
                                                    min="0"
                                                    max="20"
                                                    name="teste2"
                                                    class="form-control"
                                                    value="<?= e(
                                                        $aluno['nota_teste2']
                                                        ?? ''
                                                    ) ?>"
                                                    required>

                                            </div>


                                            <div class="mb-3">

                                                <label class="form-label">
                                                    Exame
                                                </label>

                                                <input
                                                    type="number"
                                                    step="0.1"
                                                    min="0"
                                                    max="20"
                                                    name="exame"
                                                    class="form-control"
                                                    value="<?= e(
                                                        $aluno['nota_exame']
                                                        ?? ''
                                                    ) ?>"
                                                    required>

                                            </div>


                                            <div class="alert alert-info">

                                                A média será calculada
                                                automaticamente.

                                            </div>

                                        </div>


                                        <div class="modal-footer">

                                            <button
                                                type="button"
                                                class="btn btn-secondary"
                                                data-bs-dismiss="modal">

                                                Cancelar

                                            </button>

                                            <button
                                                type="submit"
                                                name="btn_salvar_nota"
                                                class="btn btn-cacoin">

                                                Guardar Notas

                                            </button>

                                        </div>

                                    </form>

                                </div>

                            </div>

                        </div>

                    </td>

                </tr>

            <?php endforeach; ?>

            </tbody>

        </table>

    </div>

</div>


<?php endif; ?>


<!-- =========================================================
     PRESENÇAS GERAIS PROFESSOR
========================================================= -->

<?php elseif ($action === 'prof_presencas' && isProfessor()): ?>


<div class="mb-4">

    <h2 class="page-title">
        Registo de Presenças
    </h2>

    <p class="text-muted">
        Selecione uma turma para realizar a chamada.
    </p>

</div>


<div class="row g-4">

<?php

$stmt = $pdo->prepare("
    SELECT
        t.*,
        c.nome AS curso_nome,
        s.nome AS sala_nome
    FROM professor_turmas pt
    INNER JOIN turmas t
        ON pt.turma_id = t.id
    LEFT JOIN cursos c
        ON t.curso_id = c.id
    LEFT JOIN salas s
        ON t.sala_id = s.id
    WHERE pt.professor_id = ?
");

$stmt->execute([
    $_SESSION['user_id']
]);

$turmasPresenca = $stmt->fetchAll();

?>


<?php foreach ($turmasPresenca as $turma): ?>

    <div class="col-md-6 col-xl-4">

        <div class="card card-modern">

            <div class="card-body p-4">

                <h5 class="fw-bold">

                    <?= e($turma['nome']) ?>

                </h5>

                <p class="text-muted small">

                    <?= e(
                        $turma['curso_nome']
                        ?? ''
                    ) ?>

                </p>

                <a
                    href="index.php?action=prof_turma&turma_id=<?= $turma['id'] ?>&aba=presenca"
                    class="btn btn-success w-100">

                    <i class="fa-solid fa-calendar-check me-2"></i>

                    Fazer Chamada

                </a>

            </div>

        </div>

    </div>

<?php endforeach; ?>

</div>


<!-- =========================================================
     NOTAS GERAIS PROFESSOR
========================================================= -->

<?php elseif ($action === 'prof_notas' && isProfessor()): ?>


<div class="mb-4">

    <h2 class="page-title">
        Notas e Avaliações
    </h2>

    <p class="text-muted">
        Escolha uma turma para consultar e lançar notas.
    </p>

</div>


<div class="row g-4">

<?php foreach ($minhasTurmas ?? [] as $turma): ?>

    <div class="col-md-6 col-xl-4">

        <div class="card card-modern">

            <div class="card-body p-4">

                <h5 class="fw-bold">
                    <?= e($turma['nome']) ?>
                </h5>

                <p class="text-muted small">
                    <?= e(
                        $turma['curso_nome']
                        ?? ''
                    ) ?>
                </p>

                <a
                    href="index.php?action=prof_turma&turma_id=<?= $turma['id'] ?>&aba=notas"
                    class="btn btn-primary w-100">

                    <i class="fa-solid fa-file-pen me-2"></i>

                    Abrir Pauta

                </a>

            </div>

        </div>

    </div>

<?php endforeach; ?>

</div>


<?php endif; ?>


    </div>

</main>

</div>


<?php endif; ?>


<script
    src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js">
</script>


<script>

function toggleSidebar()
{
    const sidebar =
        document.getElementById('sidebar');

    if (sidebar) {

        sidebar.classList.toggle('show');

    }
}


/*
|--------------------------------------------------------------------------
| FECHAR SIDEBAR AO CLICAR FORA NO TELEMÓVEL
|--------------------------------------------------------------------------
*/

document.addEventListener(
    'click',
    function(event) {

        const sidebar =
            document.getElementById('sidebar');

        if (!sidebar) {
            return;
        }

        if (
            window.innerWidth <= 991 &&
            sidebar.classList.contains('show')
        ) {

            const clickedInside =
                sidebar.contains(event.target);

            const menuButton =
                event.target.closest('.mobile-menu');

            if (!clickedInside && !menuButton) {

                sidebar.classList.remove('show');

            }

        }

    }
);

</script>

</body>
</html>