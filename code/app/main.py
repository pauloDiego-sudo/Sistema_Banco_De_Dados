from fastapi import FastAPI, Depends, HTTPException, status, Security
from sqlalchemy.orm import Session
from typing import List, Union
from . import models, schemas, crud, database
from .database import SessionLocal, engine
from datetime import timedelta, datetime, timezone
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes
from dotenv import load_dotenv
import os
from fastapi.middleware.cors import CORSMiddleware

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------
# Rotas para Autenticação
# --------------------------------

SECRET_KEY = b"ee9a755d2d09985b09cdbebac8969efd64a95c91ed174d55ffd1768f7d9d16f9"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

# Função para criar o token JWT
def criar_token_acesso(data: dict, profile: str, user_id: int):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "profile": profile, "user_id": user_id})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Função para autenticar o usuário
async def autenticar_usuario(db: Session, form_data: OAuth2PasswordRequestForm = Depends()):
    usuario = None
    profile = None
    user_id = None

    # Check Paciente
    usuario = db.query(models.Paciente).filter(models.Paciente.email == form_data.username).first()
    if usuario and usuario.senha == form_data.password:
        profile = "Paciente"
        user_id = usuario.id_paciente
    
    # Check Medico if not found
    if not usuario:
        usuario = db.query(models.Medico).filter(models.Medico.email == form_data.username).first()
        if usuario and usuario.senha == form_data.password:
            profile = "Medico"
            user_id = usuario.id_medico
    
    # Check Admin if not found
    if not usuario:
        usuario = db.query(models.Admin).filter(models.Admin.email_admin == form_data.username).first()
        if usuario and usuario.senha_admin == form_data.password:
            profile = "Admin"
            user_id = usuario.id_admin

    if not usuario or not profile:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou senha incorretos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Use email_admin for Admin, email for others
    email = usuario.email_admin if profile == "Admin" else usuario.email
    token_acesso = criar_token_acesso(data={"sub": email}, profile=profile, user_id=user_id)
    return {"access_token": token_acesso, "token_type": "bearer"}

# Dependency para obter o usuário atual a partir do token JWT
async def obter_usuario_atual(
    security_scopes: SecurityScopes,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(database.get_db)
):
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = "Bearer"

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não foi possível validar as credenciais",
        headers={"WWW-Authenticate": authenticate_value},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        profile: str = payload.get("profile")
        user_id: int = payload.get("user_id")
        if email is None or profile is None or user_id is None:
            raise credentials_exception
        token_data = schemas.TokenData(email=email, profile=profile, user_id=user_id)
    except JWTError:
        raise credentials_exception

    if security_scopes.scopes and token_data.profile not in security_scopes.scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Não possui permissão suficiente",
            headers={"WWW-Authenticate": authenticate_value},
        )

    if token_data.profile == "Paciente":
        usuario = db.query(models.Paciente).filter(models.Paciente.email == token_data.email).first()
    elif token_data.profile == "Medico":
        usuario = db.query(models.Medico).filter(models.Medico.email == token_data.email).first()
    elif token_data.profile == "Admin":
        usuario = db.query(models.Admin).filter(models.Admin.email_admin == token_data.email).first()
    else:
        raise credentials_exception

    if usuario is None:
        raise credentials_exception
    return usuario

@app.post("/token")
async def login_para_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    return await autenticar_usuario(db, form_data)
# --------------------------------
# Rotas para Paciente
# --------------------------------

@app.post("/pacientes/", response_model=schemas.Paciente)
def criar_paciente(
    paciente: schemas.PacienteCreate, 
    db: Session = Depends(database.get_db),
    usuario_atual: models.Admin = Security(obter_usuario_atual, scopes=["Admin"])
):
    if not isinstance(usuario_atual, models.Admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Apenas administradores podem criar novos pacientes"
        )
    db_paciente = crud.criar_paciente(db=db, paciente=paciente)
    return db_paciente

@app.get("/pacientes/{id_paciente}", response_model=schemas.Paciente)
def ler_paciente(
    id_paciente: int, 
    db: Session = Depends(database.get_db),
    usuario_atual: Union[models.Paciente, models.Medico, models.Admin] = Security(obter_usuario_atual, scopes=["Paciente", "Medico", "Admin"])
):
    if isinstance(usuario_atual, models.Paciente):
        if usuario_atual.id_paciente != id_paciente:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Você só pode visualizar suas próprias informações"
            )
        return usuario_atual
    elif isinstance(usuario_atual, models.Medico):
        # Check if the Medico has a Consulta with the Paciente
        consulta = db.query(models.Consulta).filter(
            models.Consulta.id_medico == usuario_atual.id_medico,
            models.Consulta.id_paciente == id_paciente
        ).first()
        if not consulta:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Você só pode visualizar informações de pacientes com os quais tem consulta"
            )
    
    db_paciente = crud.obter_paciente(db, id_paciente=id_paciente)
    if db_paciente is None:
        raise HTTPException(status_code=404, detail="Paciente não encontrado")
    return db_paciente

@app.get("/pacientes/", response_model=List[schemas.Paciente])
def listar_pacientes(
    skip: int = 0, 
    limit: int = 100, 
    db: Session = Depends(database.get_db),
    usuario_atual: models.Admin = Security(obter_usuario_atual, scopes=["Admin"])
):
    pacientes = crud.listar_pacientes(db, skip=skip, limit=limit)
    return pacientes

@app.put("/pacientes/{id_paciente}", response_model=schemas.Paciente)
def atualizar_paciente(
    id_paciente: int, 
    paciente: schemas.PacienteBase, 
    db: Session = Depends(database.get_db),
    usuario_atual: Union[models.Paciente, models.Admin] = Security(obter_usuario_atual, scopes=["Paciente", "Admin"])
):
    if isinstance(usuario_atual, models.Paciente) and usuario_atual.id_paciente != id_paciente:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você só pode atualizar suas próprias informações"
        )
    
    db_paciente = crud.atualizar_paciente(db, id_paciente=id_paciente, paciente=paciente)
    if db_paciente is None:
        raise HTTPException(status_code=404, detail="Paciente não encontrado")
    return db_paciente

@app.delete("/pacientes/{id_paciente}", response_model=schemas.Paciente)
def deletar_paciente(
    id_paciente: int, 
    db: Session = Depends(database.get_db),
    usuario_atual: models.Admin = Security(obter_usuario_atual, scopes=["Admin"])
):
    crud.deletar_paciente(db, id_paciente=id_paciente)
    return {"message": "Paciente deletado com sucesso"}


# --------------------------------
# Rotas para Medico
# --------------------------------

@app.post("/medicos/", response_model=schemas.Medico)
def criar_medico(
    medico: schemas.MedicoCreate, 
    db: Session = Depends(database.get_db),
    usuario_atual: models.Admin = Security(obter_usuario_atual, scopes=["Admin"])
):
    if not isinstance(usuario_atual, models.Admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Apenas administradores podem criar novos médicos"
        )
    db_medico = crud.criar_medico(db=db, medico=medico)
    return db_medico

@app.get("/medicos/{id_medico}", response_model=schemas.Medico)
def ler_medico(
    id_medico: int, 
    db: Session = Depends(database.get_db),
    usuario_atual: Union[models.Medico, models.Admin] = Security(obter_usuario_atual, scopes=["Medico", "Admin"])
):
    db_medico = crud.obter_medico(db, id_medico=id_medico)
    if db_medico is None:
        raise HTTPException(status_code=404, detail="Médico não encontrado")
    return db_medico

@app.get("/medicos/", response_model=List[schemas.Medico])
def listar_medicos(
    skip: int = 0, 
    limit: int = 100, 
    db: Session = Depends(database.get_db),
    usuario_atual: Union[models.Paciente, models.Medico, models.Admin] = Security(obter_usuario_atual, scopes=["Paciente", "Medico", "Admin"])
):
    medicos = crud.listar_medicos(db, skip=skip, limit=limit)
    return medicos

@app.put("/medicos/{id_medico}", response_model=schemas.Medico)
def atualizar_medico(
    id_medico: int, 
    medico: schemas.MedicoBase, 
    db: Session = Depends(database.get_db),
    usuario_atual: Union[models.Medico, models.Admin] = Security(obter_usuario_atual, scopes=["Medico", "Admin"])
):
    if isinstance(usuario_atual, models.Medico) and usuario_atual.id_medico != id_medico:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você só pode atualizar suas próprias informações"
        )
    
    db_medico = crud.atualizar_medico(db, id_medico=id_medico, medico=medico)
    if db_medico is None:
        raise HTTPException(status_code=404, detail="Médico não encontrado")
    return db_medico

@app.delete("/medicos/{id_medico}", response_model=schemas.DeleteMessage)
def deletar_medico(
    id_medico: int, 
    db: Session = Depends(database.get_db),
    usuario_atual: models.Admin = Security(obter_usuario_atual, scopes=["Admin"])
):
    return crud.deletar_medico(db, id_medico=id_medico)


# --------------------------------
# Rotas para Consulta
# --------------------------------

@app.post("/consultas/", response_model=schemas.Consulta)
def criar_consulta(
    consulta: schemas.ConsultaCreate, 
    db: Session = Depends(database.get_db),
    usuario_atual: Union[models.Paciente, models.Medico, models.Admin] = Security(obter_usuario_atual, scopes=["Paciente", "Medico", "Admin"])
):
    # Verificar disponibilidade do médico (implementar lógica aqui)
    db_consulta = crud.criar_consulta(db=db, consulta=consulta)
    return db_consulta

@app.get("/consultas/{id_consulta}", response_model=schemas.Consulta)
def ler_consulta(
    id_consulta: int, 
    db: Session = Depends(database.get_db),
    usuario_atual: Union[models.Paciente, models.Medico, models.Admin] = Security(obter_usuario_atual, scopes=["Paciente", "Medico", "Admin"])
):
    db_consulta = crud.obter_consulta(db, id_consulta=id_consulta)
    if db_consulta is None:
        raise HTTPException(status_code=404, detail="Consulta não encontrada")
    
    # Verificar se o usuário tem permissão para ver esta consulta
    if isinstance(usuario_atual, models.Paciente) and usuario_atual.id_paciente != db_consulta.id_paciente:
        raise HTTPException(status_code=403, detail="Você não tem permissão para ver esta consulta")
    elif isinstance(usuario_atual, models.Medico) and usuario_atual.id_medico != db_consulta.id_medico:
        raise HTTPException(status_code=403, detail="Você não tem permissão para ver esta consulta")
    
    return db_consulta

@app.get("/consultas/", response_model=List[schemas.Consulta])
def listar_consultas(
    skip: int = 0, 
    limit: int = 100, 
    db: Session = Depends(database.get_db),
    usuario_atual: Union[models.Paciente, models.Medico, models.Admin] = Security(obter_usuario_atual, scopes=["Paciente", "Medico", "Admin"])
):
    if isinstance(usuario_atual, models.Admin):
        consultas = crud.listar_consultas(db, skip=skip, limit=limit)
    elif isinstance(usuario_atual, models.Medico):
        consultas = db.query(models.Consulta).filter(models.Consulta.id_medico == usuario_atual.id_medico).offset(skip).limit(limit).all()
    else:  # Paciente
        consultas = db.query(models.Consulta).filter(models.Consulta.id_paciente == usuario_atual.id_paciente).offset(skip).limit(limit).all()
    
    # Ensure all required fields are present and valid
    valid_consultas = []
    for consulta in consultas:
        if consulta.id_medico is not None and consulta.id_paciente is not None:
            valid_consultas.append(consulta)
    
    return valid_consultas

@app.put("/consultas/{id_consulta}", response_model=schemas.Consulta)
def atualizar_consulta(
    id_consulta: int, 
    consulta: schemas.ConsultaBase, 
    db: Session = Depends(database.get_db),
    usuario_atual: Union[models.Medico, models.Admin] = Security(obter_usuario_atual, scopes=["Medico", "Admin"])
):
    db_consulta = crud.obter_consulta(db, id_consulta=id_consulta)
    if db_consulta is None:
        raise HTTPException(status_code=404, detail="Consulta não encontrada")
    
    if isinstance(usuario_atual, models.Medico) and usuario_atual.id_medico != db_consulta.id_medico:
        raise HTTPException(status_code=403, detail="Você não tem permissão para atualizar esta consulta")
    
    db_consulta = crud.atualizar_consulta(db, id_consulta=id_consulta, consulta=consulta)
    return db_consulta

@app.delete("/consultas/{id_consulta}", response_model=schemas.Consulta)
def deletar_consulta(
    id_consulta: int, 
    db: Session = Depends(database.get_db),
    usuario_atual: models.Admin = Security(obter_usuario_atual, scopes=["Admin"])
):
    db_consulta = crud.deletar_consulta(db, id_consulta=id_consulta)
    if db_consulta is None:
        raise HTTPException(status_code=404, detail="Consulta não encontrada")
    return {"message": "Consulta deletada com sucesso"}


# --------------------------------
# Rotas para HorarioDisponivel
# --------------------------------

@app.post("/horarios/", response_model=schemas.HorarioDisponivel)
def criar_horario_disponivel(
    horario: schemas.HorarioDisponivelCreate, 
    db: Session = Depends(database.get_db),
    usuario_atual: Union[models.Medico, models.Admin] = Security(obter_usuario_atual, scopes=["Medico", "Admin"])
):
    if isinstance(usuario_atual, models.Medico):
        horario.id_medico = usuario_atual.id_medico
    db_horario = crud.criar_horario_disponivel(db=db, horario=horario)
    return db_horario

@app.get("/horarios/{id_horario}", response_model=schemas.HorarioDisponivel)
def ler_horario_disponivel(
    id_horario: int, 
    db: Session = Depends(database.get_db),
    usuario_atual: Union[models.Medico, models.Admin] = Security(obter_usuario_atual, scopes=["Medico", "Admin"])
):
    db_horario = crud.obter_horario_disponivel(db, id_horario=id_horario)
    if db_horario is None:
        raise HTTPException(status_code=404, detail="Horário disponível não encontrado")
    if isinstance(usuario_atual, models.Medico) and db_horario.id_medico != usuario_atual.id_medico:
        raise HTTPException(status_code=403, detail="Você não tem permissão para ver este horário")
    return db_horario

@app.get("/horarios/", response_model=List[schemas.HorarioDisponivel])
def listar_horarios_disponiveis(
    skip: int = 0, 
    limit: int = 100, 
    db: Session = Depends(database.get_db),
    usuario_atual: Union[models.Paciente, models.Medico, models.Admin] = Security(obter_usuario_atual, scopes=["Paciente", "Medico", "Admin"])
):
    if isinstance(usuario_atual, models.Admin):
        horarios = db.query(models.HorarioDisponivel).filter(models.HorarioDisponivel.id_medico.isnot(None)).offset(skip).limit(limit).all()
    elif isinstance(usuario_atual, models.Medico):
        horarios = db.query(models.HorarioDisponivel).filter(models.HorarioDisponivel.id_medico == usuario_atual.id_medico).offset(skip).limit(limit).all()
    else:  # Paciente
        horarios = db.query(models.HorarioDisponivel).filter(models.HorarioDisponivel.id_medico.isnot(None)).offset(skip).limit(limit).all()
    return horarios

@app.put("/horarios/{id_horario}", response_model=schemas.HorarioDisponivel)
def atualizar_horario_disponivel(
    id_horario: int, 
    horario: schemas.HorarioDisponivelBase, 
    db: Session = Depends(database.get_db),
    usuario_atual: Union[models.Medico, models.Admin] = Security(obter_usuario_atual, scopes=["Medico", "Admin"])
):
    db_horario = crud.obter_horario_disponivel(db, id_horario=id_horario)
    if db_horario is None:
        raise HTTPException(status_code=404, detail="Horário disponível não encontrado")
    if isinstance(usuario_atual, models.Medico) and db_horario.id_medico != usuario_atual.id_medico:
        raise HTTPException(status_code=403, detail="Você não tem permissão para atualizar este horário")
    db_horario = crud.atualizar_horario_disponivel(db, id_horario=id_horario, horario=horario)
    return db_horario

@app.delete("/horarios/{id_horario}", response_model=schemas.HorarioDisponivel)
def deletar_horario_disponivel(
    id_horario: int, 
    db: Session = Depends(database.get_db),
    usuario_atual: models.Admin = Security(obter_usuario_atual, scopes=["Admin"])
):
    crud.deletar_horario_disponivel(db, id_horario=id_horario)
    return {"message": "Horário disponível deletado com sucesso"}

@app.get("/medicos/{id_medico}/horarios", response_model=List[schemas.HorarioDisponivel])
def listar_horarios_medico(
    id_medico: int,
    db: Session = Depends(database.get_db),
    usuario_atual: Union[models.Medico, models.Admin] = Security(obter_usuario_atual, scopes=["Medico", "Admin"])
):
    if isinstance(usuario_atual, models.Medico) and usuario_atual.id_medico != id_medico:
        raise HTTPException(status_code=403, detail="Você não tem permissão para ver os horários deste médico")
    horarios = db.query(models.HorarioDisponivel).filter(models.HorarioDisponivel.id_medico == id_medico).all()
    return horarios

# --------------------------------
# Rotas para Admin
# --------------------------------

@app.post("/admins/", response_model=schemas.Admin)
def criar_admin(
    admin: schemas.AdminCreate, 
    db: Session = Depends(database.get_db),
    usuario_atual: models.Admin = Security(obter_usuario_atual, scopes=["Admin"])
):
    if not isinstance(usuario_atual, models.Admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Apenas administradores podem criar novos administradores"
        )
    db_admin = crud.criar_admin(db=db, admin=admin)
    return db_admin

@app.get("/admins/{id_admin}", response_model=schemas.Admin)
def ler_admin(
    id_admin: int, 
    db: Session = Depends(database.get_db),
    usuario_atual: models.Admin = Security(obter_usuario_atual, scopes=["Admin"])
):
    db_admin = crud.obter_admin(db, id_admin=id_admin)
    if db_admin is None:
        raise HTTPException(status_code=404, detail="Admin não encontrado")
    return db_admin

@app.get("/admins/", response_model=List[schemas.Admin])
def listar_admins(
    skip: int = 0, 
    limit: int = 100, 
    db: Session = Depends(database.get_db),
    usuario_atual: models.Admin = Security(obter_usuario_atual, scopes=["Admin"])
):
    admins = crud.listar_admins(db, skip=skip, limit=limit)
    return admins

@app.put("/admins/{id_admin}", response_model=schemas.Admin)
def atualizar_admin(
    id_admin: int, 
    admin: schemas.AdminBase, 
    db: Session = Depends(database.get_db),
    usuario_atual: models.Admin = Security(obter_usuario_atual, scopes=["Admin"])
):
    db_admin = crud.atualizar_admin(db, id_admin=id_admin, admin=admin)
    return db_admin

@app.delete("/admins/{id_admin}", response_model=schemas.Admin)
def deletar_admin(
    id_admin: int, 
    db: Session = Depends(database.get_db),
    usuario_atual: models.Admin = Security(obter_usuario_atual, scopes=["Admin"])
):
    crud.deletar_admin(db, id_admin=id_admin)
    return {"message": "Admin deletado com sucesso"}

# --------------------------------
# Rotas de Agendamento de Consultas
# --------------------------------

@app.get("/medicos/{id_medico}/horarios_disponiveis", response_model=List[schemas.HorarioDisponivel])
def listar_horarios_disponiveis_medico(
    id_medico: int, 
    db: Session = Depends(database.get_db),
    usuario_atual: Union[models.Paciente, models.Medico, models.Admin] = Security(obter_usuario_atual, scopes=["Paciente", "Medico", "Admin"])
):
    horarios = db.query(models.HorarioDisponivel).filter(models.HorarioDisponivel.id_medico == id_medico).all()
    return horarios

@app.post("/consultas/{id_medico}/agendar", response_model=schemas.Consulta)
async def agendar_consulta(
    id_medico: int, 
    consulta: schemas.ConsultaCreate, 
    db: Session = Depends(database.get_db), 
    usuario_atual: Union[models.Paciente, models.Admin] = Security(obter_usuario_atual, scopes=["Paciente", "Admin"])
):
    # Verificar disponibilidade do médico (implementar lógica aqui)
    if isinstance(usuario_atual, models.Admin):
        # If the user is an Admin, use the id_paciente from the consulta object
        consulta.id_paciente = consulta.id_paciente
    else:
        # If the user is a Paciente, use their own id
        consulta.id_paciente = usuario_atual.id_paciente
    db_consulta = crud.criar_consulta(db=db, consulta=consulta)
    return db_consulta

@app.put("/consultas/{id_consulta}/cancelar", response_model=schemas.Consulta)
async def cancelar_consulta(
    id_consulta: int, 
    db: Session = Depends(database.get_db), 
    usuario_atual: Union[models.Paciente, models.Medico, models.Admin] = Security(obter_usuario_atual, scopes=["Paciente", "Medico", "Admin"])
):
    db_consulta = crud.obter_consulta(db, id_consulta=id_consulta)
    if db_consulta is None:
        raise HTTPException(status_code=404, detail="Consulta não encontrada")
    
    if not isinstance(usuario_atual, models.Admin):
        if isinstance(usuario_atual, models.Paciente) and usuario_atual.id_paciente != db_consulta.id_paciente:
            raise HTTPException(status_code=403, detail="Você não tem permissão para cancelar esta consulta")
        elif isinstance(usuario_atual, models.Medico) and usuario_atual.id_medico != db_consulta.id_medico:
            raise HTTPException(status_code=403, detail="Você não tem permissão para cancelar esta consulta")

    # Cancel the consulta
    db_consulta.status = "cancelada"
    db.add(db_consulta)
    db.commit()
    db.refresh(db_consulta)
    return db_consulta

@app.get("/pacientes/{id_paciente}/consultas", response_model=List[schemas.Consulta])
async def listar_consultas_paciente(
    id_paciente: int,
    db: Session = Depends(database.get_db),
    usuario_atual: Union[models.Paciente, models.Admin] = Security(obter_usuario_atual, scopes=["Paciente", "Admin"])
):
    if not isinstance(usuario_atual, models.Admin) and usuario_atual.id_paciente != id_paciente:
        raise HTTPException(status_code=403, detail="Você não tem permissão para acessar as consultas deste paciente")

    consultas = db.query(models.Consulta).filter(models.Consulta.id_paciente == id_paciente).all()
    return consultas

@app.get("/medicos/{id_medico}/consultas", response_model=List[schemas.Consulta])
async def listar_consultas_medico(
    id_medico: int,
    db: Session = Depends(database.get_db),
    usuario_atual: Union[models.Medico, models.Admin] = Security(obter_usuario_atual, scopes=["Medico", "Admin"])
):
    # Verificar se o usuário atual é o médico ou um administrador
    if isinstance(usuario_atual, models.Medico) and usuario_atual.id_medico != id_medico:
        raise HTTPException(status_code=403, detail="Você não tem permissão para acessar as consultas deste médico")

    # Obter as consultas do médico
    consultas = db.query(models.Consulta).filter(models.Consulta.id_medico == id_medico).all()
    return consultas

@app.put("/consultas/{id_consulta}/confirmar", response_model=schemas.Consulta)
async def confirmar_consulta(
    id_consulta: int, 
    db: Session = Depends(database.get_db), 
    usuario_atual: Union[models.Paciente, models.Medico, models.Admin] = Security(obter_usuario_atual, scopes=["Paciente", "Medico", "Admin"])
):
    db_consulta = crud.obter_consulta(db, id_consulta=id_consulta)
    if db_consulta is None:
        raise HTTPException(status_code=404, detail="Consulta não encontrada")

    if not isinstance(usuario_atual, models.Admin):
        if isinstance(usuario_atual, models.Paciente) and usuario_atual.id_paciente != db_consulta.id_paciente:
            raise HTTPException(status_code=403, detail="Você não tem permissão para confirmar esta consulta")
        elif isinstance(usuario_atual, models.Medico) and usuario_atual.id_medico != db_consulta.id_medico:
            raise HTTPException(status_code=403, detail="Você não tem permissão para confirmar esta consulta")

    db_consulta.status = "confirmada"
    db.add(db_consulta)
    db.commit()
    db.refresh(db_consulta)
    return db_consulta

@app.put("/consultas/{id_consulta}/iniciar", response_model=schemas.Consulta)
async def iniciar_consulta(
    id_consulta: int, 
    db: Session = Depends(database.get_db), 
    usuario_atual: Union[models.Medico, models.Admin] = Security(obter_usuario_atual, scopes=["Medico", "Admin"])
):
    db_consulta = crud.obter_consulta(db, id_consulta=id_consulta)
    if db_consulta is None:
        raise HTTPException(status_code=404, detail="Consulta não encontrada")

    if isinstance(usuario_atual, models.Medico) and usuario_atual.id_medico != db_consulta.id_medico:
        raise HTTPException(status_code=403, detail="Você não tem permissão para iniciar esta consulta")

    if db_consulta.status != "confirmada":
        raise HTTPException(status_code=400, detail="Consulta não pode ser iniciada pois não está confirmada")

    db_consulta.status = "em andamento"
    db.add(db_consulta)
    db.commit()
    db.refresh(db_consulta)
    return db_consulta

@app.put("/consultas/{id_consulta}/finalizar", response_model=schemas.Consulta)
async def finalizar_consulta(
    id_consulta: int, 
    observacoes: str, 
    db: Session = Depends(database.get_db), 
    usuario_atual: Union[models.Medico, models.Admin] = Security(obter_usuario_atual, scopes=["Medico", "Admin"])
):
    db_consulta = crud.obter_consulta(db, id_consulta=id_consulta)
    if db_consulta is None:
        raise HTTPException(status_code=404, detail="Consulta não encontrada")

    if isinstance(usuario_atual, models.Medico) and usuario_atual.id_medico != db_consulta.id_medico:
        raise HTTPException(status_code=403, detail="Você não tem permissão para finalizar esta consulta")

    if db_consulta.status != "em andamento":
        raise HTTPException(status_code=400, detail="Consulta não pode ser finalizada pois não está em andamento")

    db_consulta.status = "finalizada"
    db_consulta.observacoes = observacoes
    db.add(db_consulta)
    db.commit()
    db.refresh(db_consulta)
    return db_consulta

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

# @app.get("/pacientes/{id_paciente}/consultas", response_model=List[schemas.Consulta])
# async def listar_consultas_paciente(
#     id_paciente: int,
#     db: Session = Depends(database.get_db),
#     usuario_atual: models.Paciente = Security(obter_usuario_atual, scopes=["Paciente", "Admin"])
# ):
#     # 1. Verificar se o usuário atual é o paciente ou um administrador
#     if usuario_atual.id_paciente != id_paciente and not isinstance(usuario_atual, models.Admin):
#         raise HTTPException(status_code=403, detail="Você não tem permissão para acessar as consultas deste paciente")

#     # 2. Obter as consultas do paciente
#     consultas = db.query(models.Consulta).filter(models.Consulta.id_paciente == id_paciente).all()
#     return consultas

# @app.get("/medicos/{id_medico}/consultas", response_model=List[schemas.Consulta])
# async def listar_consultas_medico(
#     id_medico: int,
#     db: Session = Depends(database.get_db),
#     usuario_atual: Union[models.Medico, models.Admin] = Security(obter_usuario_atual, scopes=["Medico", "Admin"])
# ):
#     # Verificar se o usuário atual é o médico ou um administrador
#     if isinstance(usuario_atual, models.Medico):
#         if usuario_atual.id_medico != id_medico:
#             raise HTTPException(status_code=403, detail="Você só pode listar suas próprias consultas")
#         # Médico listando suas próprias consultas
#         consultas = db.query(models.Consulta).filter(models.Consulta.id_medico == usuario_atual.id_medico).all()
#     else:
#         # Administrador pode listar consultas de qualquer médico
#         consultas = db.query(models.Consulta).filter(models.Consulta.id_medico == id_medico).all()
    
#     return consultas

# @app.put("/consultas/{id_consulta}/confirmar", response_model=schemas.Consulta)
# async def confirmar_consulta(id_consulta: int, db: Session = Depends(database.get_db), usuario_atual: models.Medico = Depends(obter_usuario_atual)):
#     # 1. Verificar se o usuário atual é o médico da consulta
#     db_consulta = crud.obter_consulta(db, id_consulta=id_consulta)
#     if db_consulta is None:
#         raise HTTPException(status_code=404, detail="Consulta não encontrada")

#     if usuario_atual.id_medico != db_consulta.id_medico:
#         raise HTTPException(status_code=403, detail="Você não tem permissão para confirmar esta consulta")

#     # 2. Confirmar a consulta
#     db_consulta.status = "confirmada"
#     db.add(db_consulta)
#     db.commit()
#     db.refresh(db_consulta)
#     return db_consulta

# @app.put("/consultas/{id_consulta}/iniciar", response_model=schemas.Consulta)
# async def iniciar_consulta(id_consulta: int, db: Session = Depends(database.get_db), usuario_atual: Union[models.Medico, models.Admin] = Security(obter_usuario_atual, scopes=["Medico", "Admin"])):
#     db_consulta = crud.obter_consulta(db, id_consulta=id_consulta)
#     if db_consulta is None:
#         raise HTTPException(status_code=404, detail="Consulta não encontrada")

#     if isinstance(usuario_atual, models.Medico) and usuario_atual.id_medico != db_consulta.id_medico:
#         raise HTTPException(status_code=403, detail="Você não tem permissão para iniciar esta consulta")

#     if db_consulta.status != "confirmada":
#         raise HTTPException(status_code=400, detail="Consulta não pode ser iniciada pois não está confirmada")

#     db_consulta.status = "em andamento"
#     db.add(db_consulta)
#     db.commit()
#     db.refresh(db_consulta)
#     return db_consulta

# @app.put("/consultas/{id_consulta}/finalizar", response_model=schemas.Consulta)
# async def finalizar_consulta(id_consulta: int, observacoes: str, db: Session = Depends(database.get_db), usuario_atual: Union[models.Medico, models.Admin] = Security(obter_usuario_atual, scopes=["Medico", "Admin"])):
#     db_consulta = crud.obter_consulta(db, id_consulta=id_consulta)
#     if db_consulta is None:
#         raise HTTPException(status_code=404, detail="Consulta não encontrada")

#     if isinstance(usuario_atual, models.Medico) and usuario_atual.id_medico != db_consulta.id_medico:
#         raise HTTPException(status_code=403, detail="Você não tem permissão para finalizar esta consulta")

#     if db_consulta.status != "em andamento":
#         raise HTTPException(status_code=400, detail="Consulta não pode ser finalizada pois não está em andamento")

#     db_consulta.status = "finalizada"
#     db_consulta.observacoes = observacoes
#     db.add(db_consulta)
#     db.commit()
#     db.refresh(db_consulta)
#     return db_consulta
