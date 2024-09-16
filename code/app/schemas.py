from pydantic import BaseModel
from typing import Optional, List
from datetime import date, time

# Schemas para Paciente

class PacienteBase(BaseModel):
    nome: str
    email: str
    telefone: Optional[str] = None
    data_de_nascimento: date
    cpf: str

class PacienteCreate(PacienteBase):
    senha: str

class Paciente(PacienteBase):
    id_paciente: int

    class Config:
        orm_mode = True

# Schemas para Medico

class MedicoBase(BaseModel):
    nome: str
    email: str
    especialidade: str
    telefone: Optional[str] = None
    crm: str

class MedicoCreate(MedicoBase):
    senha: str

class Medico(MedicoBase):
    id_medico: int

    class Config:
        orm_mode = True

# Schemas para Consulta

class ConsultaBase(BaseModel):
    id_paciente: int
    id_medico: int
    data_consulta: date
    horario_consulta: time
    status: Optional[str] = "agendada"
    observacoes: Optional[str] = None

class ConsultaCreate(ConsultaBase):
    pass

class Consulta(ConsultaBase):
    id_consulta: int

    class Config:
        orm_mode = True

# Schemas para HorarioDisponivel

class HorarioDisponivelBase(BaseModel):
    id_medico: int
    data_disponivel: date
    horario_inicial: time
    horario_final: time

class HorarioDisponivelCreate(HorarioDisponivelBase):
    pass

class HorarioDisponivel(HorarioDisponivelBase):
    id_horario: int

    class Config:
        orm_mode = True

# Schemas para Admin

class AdminBase(BaseModel):
    nome_admin: str
    email_admin: str

class AdminCreate(AdminBase):
    senha_admin: str

class Admin(AdminBase):
    id_admin: int

    class Config:
        orm_mode = True

class TokenData(BaseModel):
    email: Optional[str] = None
    profile: Optional[str] = None