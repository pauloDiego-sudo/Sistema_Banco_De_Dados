from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from . import models, schemas, crud, database
from .database import SessionLocal, engine
from datetime import timedelta, datetime, timezone
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from dotenv import load_dotenv
import os

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# --------------------------------
# Rotas para Autenticação
# --------------------------------

SECRET_KEY = b"ee9a755d2d09985b09cdbebac8969efd64a95c91ed174d55ffd1768f7d9d16f9"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Função para criar o token JWT
# Função para criar o token JWT
def criar_token_acesso(data: dict):
    """
    Cria um token JWT (JSON Web Token) de acesso.

    Args:
        data: Dados a serem codificados no token.
        expires_delta: Tempo de expiração do token. Se None, usa ACCESS_TOKEN_EXPIRE_MINUTES.

    Returns:
        str: Token JWT codificado.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Função para autenticar o usuário
async def autenticar_usuario(db: Session, form_data: OAuth2PasswordRequestForm = Depends()):
    usuario = db.query(models.Paciente).filter(models.Paciente.email == form_data.username).first()
    if not usuario or usuario.senha != form_data.password: # Substitua por verificação de hash de senha em produção!
        usuario = db.query(models.Medico).filter(models.Medico.email == form_data.username).first()
        if not usuario or usuario.senha != form_data.password:
            usuario = db.query(models.Admin).filter(models.Admin.email_admin == form_data.username).first()
            if not usuario or usuario.senha_admin != form_data.password:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Email ou senha incorretos",
                    headers={"WWW-Authenticate": "Bearer"},
                )
    
    token_acesso = criar_token_acesso(data={"sub": usuario.email}) # Use o email como subject do token
    return {"access_token": token_acesso, "token_type": "bearer"}

# Dependency para obter o usuário atual a partir do token JWT
async def obter_usuario_atual(token: str = Depends(oauth2_scheme), db: Session = Depends(database.get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não foi possível validar as credenciais",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = schemas.TokenData(email=email)
    except JWTError:
        raise credentials_exception
    usuario = db.query(models.Paciente).filter(models.Paciente.email == token_data.email).first()
    if not usuario:
        usuario = db.query(models.Medico).filter(models.Medico.email == token_data.email).first()
        if not usuario:
            usuario = db.query(models.Admin).filter(models.Admin.email_admin == token_data.email).first()
            if not usuario:
                raise credentials_exception
    return usuario

@app.post("/token")
async def login_para_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    return await autenticar_usuario(db, form_data)
# --------------------------------
# Rotas para Paciente
# --------------------------------

@app.post("/pacientes/", response_model=schemas.Paciente)
def criar_paciente(paciente: schemas.PacienteCreate, db: Session = Depends(database.get_db)):
    db_paciente = crud.criar_paciente(db=db, paciente=paciente)
    return db_paciente

@app.get("/pacientes/{id_paciente}", response_model=schemas.Paciente)
def ler_paciente(id_paciente: int, db: Session = Depends(database.get_db)):
    db_paciente = crud.obter_paciente(db, id_paciente=id_paciente)
    if db_paciente is None:
        raise HTTPException(status_code=404, detail="Paciente não encontrado")
    return db_paciente

@app.get("/pacientes/", response_model=List[schemas.Paciente])
def listar_pacientes(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db)):
    pacientes = crud.listar_pacientes(db, skip=skip, limit=limit)
    return pacientes

@app.put("/pacientes/{id_paciente}", response_model=schemas.Paciente)
def atualizar_paciente(id_paciente: int, paciente: schemas.PacienteBase, db: Session = Depends(database.get_db)):
    db_paciente = crud.atualizar_paciente(db, id_paciente=id_paciente, paciente=paciente)
    return db_paciente

@app.delete("/pacientes/{id_paciente}", response_model=schemas.Paciente)
def deletar_paciente(id_paciente: int, db: Session = Depends(database.get_db)):
    crud.deletar_paciente(db, id_paciente=id_paciente)
    return {"message": "Paciente deletado com sucesso"}


# --------------------------------
# Rotas para Medico
# --------------------------------

@app.post("/medicos/", response_model=schemas.Medico)
def criar_medico(medico: schemas.MedicoCreate, db: Session = Depends(database.get_db)):
    db_medico = crud.criar_medico(db=db, medico=medico)
    return db_medico

@app.get("/medicos/{id_medico}", response_model=schemas.Medico)
def ler_medico(id_medico: int, db: Session = Depends(database.get_db)):
    db_medico = crud.obter_medico(db, id_medico=id_medico)
    if db_medico is None:
        raise HTTPException(status_code=404, detail="Médico não encontrado")
    return db_medico

@app.get("/medicos/", response_model=List[schemas.Medico])
def listar_medicos(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db)):
    medicos = crud.listar_medicos(db, skip=skip, limit=limit)
    return medicos

@app.put("/medicos/{id_medico}", response_model=schemas.Medico)
def atualizar_medico(id_medico: int, medico: schemas.MedicoBase, db: Session = Depends(database.get_db)):
    db_medico = crud.atualizar_medico(db, id_medico=id_medico, medico=medico)
    return db_medico

@app.delete("/medicos/{id_medico}", response_model=schemas.Medico)
def deletar_medico(id_medico: int, db: Session = Depends(database.get_db)):
    crud.deletar_medico(db, id_medico=id_medico)
    return {"message": "Médico deletado com sucesso"}


# --------------------------------
# Rotas para Consulta
# --------------------------------

@app.post("/consultas/", response_model=schemas.Consulta)
def criar_consulta(consulta: schemas.ConsultaCreate, db: Session = Depends(database.get_db)):
    # Verificar disponibilidade do médico (implementar lógica aqui)
    db_consulta = crud.criar_consulta(db=db, consulta=consulta)
    return db_consulta

@app.get("/consultas/{id_consulta}", response_model=schemas.Consulta)
def ler_consulta(id_consulta: int, db: Session = Depends(database.get_db)):
    db_consulta = crud.obter_consulta(db, id_consulta=id_consulta)
    if db_consulta is None:
        raise HTTPException(status_code=404, detail="Consulta não encontrada")
    return db_consulta

@app.get("/consultas/", response_model=List[schemas.Consulta])
def listar_consultas(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db)):
    consultas = crud.listar_consultas(db, skip=skip, limit=limit)
    return consultas

@app.put("/consultas/{id_consulta}", response_model=schemas.Consulta)
def atualizar_consulta(id_consulta: int, consulta: schemas.ConsultaBase, db: Session = Depends(database.get_db)):
    db_consulta = crud.atualizar_consulta(db, id_consulta=id_consulta, consulta=consulta)
    return db_consulta

@app.delete("/consultas/{id_consulta}", response_model=schemas.Consulta)
def deletar_consulta(id_consulta: int, db: Session = Depends(database.get_db)):
    crud.deletar_consulta(db, id_consulta=id_consulta)
    return {"message": "Consulta deletada com sucesso"}


# --------------------------------
# Rotas para HorarioDisponivel
# --------------------------------

@app.post("/horarios/", response_model=schemas.HorarioDisponivel)
def criar_horario_disponivel(horario: schemas.HorarioDisponivelCreate, db: Session = Depends(database.get_db)):
    db_horario = crud.criar_horario_disponivel(db=db, horario=horario)
    return db_horario

@app.get("/horarios/{id_horario}", response_model=schemas.HorarioDisponivel)
def ler_horario_disponivel(id_horario: int, db: Session = Depends(database.get_db)):
    db_horario = crud.obter_horario_disponivel(db, id_horario=id_horario)
    if db_horario is None:
        raise HTTPException(status_code=404, detail="Horário disponível não encontrado")
    return db_horario

@app.get("/horarios/", response_model=List[schemas.HorarioDisponivel])
def listar_horarios_disponiveis(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db)):
    horarios = crud.listar_horarios_disponiveis(db, skip=skip, limit=limit)
    return horarios

@app.put("/horarios/{id_horario}", response_model=schemas.HorarioDisponivel)
def atualizar_horario_disponivel(id_horario: int, horario: schemas.HorarioDisponivelBase, db: Session = Depends(database.get_db)):
    db_horario = crud.atualizar_horario_disponivel(db, id_horario=id_horario, horario=horario)
    return db_horario

@app.delete("/horarios/{id_horario}", response_model=schemas.HorarioDisponivel)
def deletar_horario_disponivel(id_horario: int, db: Session = Depends(database.get_db)):
    crud.deletar_horario_disponivel(db, id_horario=id_horario)
    return {"message": "Horário disponível deletado com sucesso"}


# --------------------------------
# Rotas para Admin
# --------------------------------

@app.post("/admins/", response_model=schemas.Admin)
def criar_admin(admin: schemas.AdminCreate, db: Session = Depends(database.get_db)):
    db_admin = crud.criar_admin(db=db, admin=admin)
    return db_admin

@app.get("/admins/{id_admin}", response_model=schemas.Admin)
def ler_admin(id_admin: int, db: Session = Depends(database.get_db)):
    db_admin = crud.obter_admin(db, id_admin=id_admin)
    if db_admin is None:
        raise HTTPException(status_code=404, detail="Admin não encontrado")
    return db_admin

@app.get("/admins/", response_model=List[schemas.Admin])
def listar_admins(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db)):
    admins = crud.listar_admins(db, skip=skip, limit=limit)
    return admins

@app.put("/admins/{id_admin}", response_model=schemas.Admin)
def atualizar_admin(id_admin: int, admin: schemas.AdminBase, db: Session = Depends(database.get_db)):
    db_admin = crud.atualizar_admin(db, id_admin=id_admin, admin=admin)
    return db_admin

@app.delete("/admins/{id_admin}", response_model=schemas.Admin)
def deletar_admin(id_admin: int, db: Session = Depends(database.get_db)):
    crud.deletar_admin(db, id_admin=id_admin)
    return {"message": "Admin deletado com sucesso"}

# --------------------------------
# Rotas de Agendamento de Consultas
# --------------------------------

@app.get("/medicos/{id_medico}/horarios_disponiveis", response_model=List[schemas.HorarioDisponivel])
def listar_horarios_disponiveis_medico(id_medico: int, db: Session = Depends(database.get_db)):
    horarios = db.query(models.HorarioDisponivel).filter(models.HorarioDisponivel.id_medico == id_medico).all()
    return horarios

@app.post("/consultas/{id_medico}/agendar", response_model=schemas.Consulta)
async def agendar_consulta(id_medico: int, consulta: schemas.ConsultaCreate, 
                         db: Session = Depends(database.get_db), usuario_atual: models.Paciente = Depends(obter_usuario_atual)):
    # 1. Verificar se o médico existe
    db_medico = crud.obter_medico(db, id_medico=id_medico)
    if db_medico is None:
        raise HTTPException(status_code=404, detail="Médico não encontrado")

    # 2. Verificar se o horário está disponível
    horario_disponivel = db.query(models.HorarioDisponivel).filter(
        models.HorarioDisponivel.id_medico == id_medico,
        models.HorarioDisponivel.data_disponivel == consulta.data_consulta,
        models.HorarioDisponivel.horario_inicial <= consulta.horario_consulta,
        models.HorarioDisponivel.horario_final >= consulta.horario_consulta
    ).first()

    if horario_disponivel is None:
        raise HTTPException(status_code=400, detail="Horário não disponível para este médico")

    # 3. Verificar se o paciente já possui uma consulta agendada no mesmo horário
    consulta_existente = db.query(models.Consulta).filter(
        models.Consulta.id_paciente == usuario_atual.id_paciente,
        models.Consulta.data_consulta == consulta.data_consulta,
        models.Consulta.horario_consulta == consulta.horario_consulta
    ).first()

    if consulta_existente:
        raise HTTPException(status_code=400, detail="Paciente já possui uma consulta agendada neste horário")

    # 4. Criar a consulta
    consulta.id_paciente = usuario_atual.id_paciente
    consulta.id_medico = id_medico 
    db_consulta = crud.criar_consulta(db=db, consulta=consulta)

    return db_consulta

@app.put("/consultas/{id_consulta}/cancelar", response_model=schemas.Consulta)
async def cancelar_consulta(id_consulta: int, db: Session = Depends(database.get_db), usuario_atual: models.Paciente = Depends(obter_usuario_atual)):
    db_consulta = crud.obter_consulta(db, id_consulta=id_consulta)
    if db_consulta is None:
        raise HTTPException(status_code=404, detail="Consulta não encontrada")
    
    # 1. Verificar se o usuário atual é o paciente ou o médico da consulta
    if usuario_atual.id_paciente != db_consulta.id_paciente and not isinstance(usuario_atual, models.Medico) and usuario_atual.id_medico != db_consulta.id_medico:
        raise HTTPException(status_code=403, detail="Você não tem permissão para cancelar esta consulta")

    # 2. Cancelar a consulta
    db_consulta.status = "cancelada"
    db.add(db_consulta)
    db.commit()
    db.refresh(db_consulta)
    return db_consulta

# --------------------------------
# Rotas de Gerenciamento de Consultas
# --------------------------------

@app.get("/pacientes/{id_paciente}/consultas", response_model=List[schemas.Consulta])
async def listar_consultas_paciente(id_paciente: int, db: Session = Depends(database.get_db), usuario_atual: models.Paciente = Depends(obter_usuario_atual)):
    # 1. Verificar se o usuário atual é o paciente ou um administrador
    if usuario_atual.id_paciente != id_paciente and not isinstance(usuario_atual, models.Admin):
        raise HTTPException(status_code=403, detail="Você não tem permissão para acessar as consultas deste paciente")

    # 2. Obter as consultas do paciente
    consultas = db.query(models.Consulta).filter(models.Consulta.id_paciente == id_paciente).all()
    return consultas

@app.get("/medicos/{id_medico}/consultas", response_model=List[schemas.Consulta])
async def listar_consultas_medico(id_medico: int, db: Session = Depends(database.get_db), usuario_atual: models.Medico = Depends(obter_usuario_atual)):
    # 1. Verificar se o usuário atual é o médico ou um administrador
    if isinstance(usuario_atual, models.Medico) and usuario_atual.id_medico != id_medico and not isinstance(usuario_atual, models.Admin):
        raise HTTPException(status_code=403, detail="Você não tem permissão para acessar as consultas deste médico")

    # 2. Obter as consultas do médico
    consultas = db.query(models.Consulta).filter(models.Consulta.id_medico == id_medico).all()
    return consultas

@app.put("/consultas/{id_consulta}/confirmar", response_model=schemas.Consulta)
async def confirmar_consulta(id_consulta: int, db: Session = Depends(database.get_db), usuario_atual: models.Medico = Depends(obter_usuario_atual)):
    # 1. Verificar se o usuário atual é o médico da consulta
    db_consulta = crud.obter_consulta(db, id_consulta=id_consulta)
    if db_consulta is None:
        raise HTTPException(status_code=404, detail="Consulta não encontrada")

    if usuario_atual.id_medico != db_consulta.id_medico:
        raise HTTPException(status_code=403, detail="Você não tem permissão para confirmar esta consulta")

    # 2. Confirmar a consulta
    db_consulta.status = "confirmada"
    db.add(db_consulta)
    db.commit()
    db.refresh(db_consulta)
    return db_consulta

@app.put("/consultas/{id_consulta}/iniciar", response_model=schemas.Consulta)
async def iniciar_consulta(id_consulta: int, db: Session = Depends(database.get_db), usuario_atual: models.Medico = Depends(obter_usuario_atual)):
    # 1. Verificar se o usuário atual é o médico da consulta
    db_consulta = crud.obter_consulta(db, id_consulta=id_consulta)
    if db_consulta is None:
        raise HTTPException(status_code=404, detail="Consulta não encontrada")

    if usuario_atual.id_medico != db_consulta.id_medico:
        raise HTTPException(status_code=403, detail="Você não tem permissão para iniciar esta consulta")

    # 2. Verificar se a consulta está confirmada
    if db_consulta.status != "confirmada":
        raise HTTPException(status_code=400, detail="Consulta não pode ser iniciada pois não está confirmada")

    # 3. Iniciar a consulta
    db_consulta.status = "em andamento"
    db.add(db_consulta)
    db.commit()
    db.refresh(db_consulta)
    return db_consulta

@app.put("/consultas/{id_consulta}/finalizar", response_model=schemas.Consulta)
async def finalizar_consulta(id_consulta: int, observacoes: str, db: Session = Depends(database.get_db), usuario_atual: models.Medico = Depends(obter_usuario_atual)):
    # 1. Verificar se o usuário atual é o médico da consulta
    db_consulta = crud.obter_consulta(db, id_consulta=id_consulta)
    if db_consulta is None:
        raise HTTPException(status_code=404, detail="Consulta não encontrada")

    if usuario_atual.id_medico != db_consulta.id_medico:
        raise HTTPException(status_code=403, detail="Você não tem permissão para finalizar esta consulta")

    # 2. Verificar se a consulta está em andamento
    if db_consulta.status != "em andamento":
        raise HTTPException(status_code=400, detail="Consulta não pode ser finalizada pois não está em andamento")

    # 3. Finalizar a consulta
    db_consulta.status = "finalizada"
    db_consulta.observacoes = observacoes
    db.add(db_consulta)
    db.commit()
    db.refresh(db_consulta)
    return db_consulta
