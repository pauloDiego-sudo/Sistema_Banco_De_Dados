from sqlalchemy.orm import Session
from . import models, schemas
from sqlalchemy.exc import SQLAlchemyError

# --------------------------------
# CRUD para Paciente
# --------------------------------

def criar_paciente(db: Session, paciente: schemas.PacienteCreate):
    db_paciente = models.Paciente(
        nome=paciente.nome,
        email=paciente.email,
        telefone=paciente.telefone,
        data_de_nascimento=paciente.data_de_nascimento,
        cpf=paciente.cpf,
        senha=paciente.senha  # Hash the password in a real application!
    )
    try:
        db.add(db_paciente)
        db.commit()  # Apenas neste ponto a transação será confirmada.
        db.refresh(db_paciente)  # Atualiza o objeto com o ID gerado pelo banco de dados.
        return db_paciente
    except SQLAlchemyError:
        db.rollback()  # Reverte a transação em caso de erro.
        raise

def obter_paciente(db: Session, id_paciente: int):
    return db.query(models.Paciente).filter(models.Paciente.id_paciente == id_paciente).first()

def listar_pacientes(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Paciente).offset(skip).limit(limit).all()

def atualizar_paciente(db: Session, id_paciente: int, paciente: schemas.PacienteBase):
    db_paciente = obter_paciente(db, id_paciente=id_paciente)
    if db_paciente is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Paciente não encontrado")

    for var, value in vars(paciente).items():
        setattr(db_paciente, var, value) if value else None

    db.add(db_paciente)
    db.commit()
    db.refresh(db_paciente)
    return db_paciente

def deletar_paciente(db: Session, id_paciente: int):
    db_paciente = obter_paciente(db, id_paciente=id_paciente)
    if db_paciente is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Paciente não encontrado")

    db.delete(db_paciente)
    db.commit()
    return {"message": "Paciente deletado com sucesso"}


# --------------------------------
# CRUD para Medico
# --------------------------------

def criar_medico(db: Session, medico: schemas.MedicoCreate):
    db_medico = models.Medico(
        nome=medico.nome,
        email=medico.email,
        especialidade=medico.especialidade,
        telefone=medico.telefone,
        crm=medico.crm,
        senha=medico.senha  # Hash the password in a real application!
    )
    db.add(db_medico)
    db.commit()
    db.refresh(db_medico)
    return db_medico

def obter_medico(db: Session, id_medico: int):
    return db.query(models.Medico).filter(models.Medico.id_medico == id_medico).first()

def listar_medicos(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Medico).offset(skip).limit(limit).all()

def atualizar_medico(db: Session, id_medico: int, medico: schemas.MedicoBase):
    db_medico = obter_medico(db, id_medico=id_medico)
    if db_medico is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Médico não encontrado")

    for var, value in vars(medico).items():
        setattr(db_medico, var, value) if value else None

    db.add(db_medico)
    db.commit()
    db.refresh(db_medico)
    return db_medico


def deletar_medico(db: Session, id_medico: int):
    db_medico = obter_medico(db, id_medico=id_medico)
    if db_medico is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Médico não encontrado")

    db.delete(db_medico)
    db.commit()
    return {"message": "Médico deletado com sucesso"}

# --------------------------------
# CRUD para Consulta
# --------------------------------

def criar_consulta(db: Session, consulta: schemas.ConsultaCreate):
    db_consulta = models.Consulta(**consulta.dict())
    db.add(db_consulta)
    db.commit()
    db.refresh(db_consulta)
    return db_consulta

def obter_consulta(db: Session, id_consulta: int):
    return db.query(models.Consulta).filter(models.Consulta.id_consulta == id_consulta).first()

def listar_consultas(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Consulta).offset(skip).limit(limit).all()


def atualizar_consulta(db: Session, id_consulta: int, consulta: schemas.ConsultaBase):
    db_consulta = obter_consulta(db, id_consulta=id_consulta)
    if db_consulta is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Consulta não encontrada")

    for var, value in vars(consulta).items():
        setattr(db_consulta, var, value) if value else None

    db.add(db_consulta)
    db.commit()
    db.refresh(db_consulta)
    return db_consulta


def deletar_consulta(db: Session, id_consulta: int):
    db_consulta = obter_consulta(db, id_consulta=id_consulta)
    if db_consulta is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Consulta não encontrada")

    db.delete(db_consulta)
    db.commit()
    return {"message": "Consulta deletada com sucesso"}

# --------------------------------
# CRUD para HorarioDisponivel
# --------------------------------

def criar_horario_disponivel(db: Session, horario: schemas.HorarioDisponivelCreate):
    db_horario = models.HorarioDisponivel(**horario.dict())
    db.add(db_horario)
    db.commit()
    db.refresh(db_horario)
    return db_horario

def obter_horario_disponivel(db: Session, id_horario: int):
    return db.query(models.HorarioDisponivel).filter(models.HorarioDisponivel.id_horario == id_horario).first()

def listar_horarios_disponiveis(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.HorarioDisponivel).offset(skip).limit(limit).all()

def atualizar_horario_disponivel(db: Session, id_horario: int, horario: schemas.HorarioDisponivelBase):
    db_horario = obter_horario_disponivel(db, id_horario=id_horario)
    if db_horario is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Horário disponível não encontrado")

    for var, value in vars(horario).items():
        setattr(db_horario, var, value) if value else None

    db.add(db_horario)
    db.commit()
    db.refresh(db_horario)
    return db_horario

def deletar_horario_disponivel(db: Session, id_horario: int):
    db_horario = obter_horario_disponivel(db, id_horario=id_horario)
    if db_horario is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Horário disponível não encontrado")

    db.delete(db_horario)
    db.commit()
    return {"message": "Horário disponível deletado com sucesso"}

# --------------------------------
# CRUD para Admin
# --------------------------------

def criar_admin(db: Session, admin: schemas.AdminCreate):
    db_admin = models.Admin(
        nome_admin=admin.nome_admin,
        email_admin=admin.email_admin,
        senha_admin=admin.senha_admin  # Hash the password in a real application!
    )
    db.add(db_admin)
    db.commit()
    db.refresh(db_admin)
    return db_admin

def obter_admin(db: Session, id_admin: int):
    return db.query(models.Admin).filter(models.Admin.id_admin == id_admin).first()

def listar_admins(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Admin).offset(skip).limit(limit).all()

def atualizar_admin(db: Session, id_admin: int, admin: schemas.AdminBase):
    db_admin = obter_admin(db, id_admin=id_admin)
    if db_admin is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Admin não encontrado")

    for var, value in vars(admin).items():
        setattr(db_admin, var, value) if value else None

    db.add(db_admin)
    db.commit()
    db.refresh(db_admin)
    return db_admin

def deletar_admin(db: Session, id_admin: int):
    db_admin = obter_admin(db, id_admin=id_admin)
    if db_admin is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Admin não encontrado")

    db.delete(db_admin)
    db.commit()
    return {"message": "Admin deletado com sucesso"}