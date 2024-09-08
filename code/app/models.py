from sqlalchemy import Column, Integer, String, Date, Time, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship
from .database import Base

class Paciente(Base):
    __tablename__ = "paciente"

    id_paciente = Column(Integer, primary_key=True, index=True)
    nome = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    telefone = Column(String(15))
    data_de_nascimento = Column(Date, nullable=False)
    cpf = Column(String(11), unique=True, nullable=False)
    senha = Column(String(100), nullable=False)

    consultas = relationship("Consulta", back_populates="paciente")

class Medico(Base):
    __tablename__ = "medico"

    id_medico = Column(Integer, primary_key=True, index=True)
    nome = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    especialidade = Column(String(100), nullable=False)
    telefone = Column(String(15))
    crm = Column(String(10), unique=True, nullable=False)
    senha = Column(String(100), nullable=False)

    consultas = relationship("Consulta", back_populates="medico")
    horarios_disponiveis = relationship("HorarioDisponivel", back_populates="medico")

class Consulta(Base):
    __tablename__ = "consulta"

    id_consulta = Column(Integer, primary_key=True, index=True)
    id_paciente = Column(Integer, ForeignKey("paciente.id_paciente"))
    id_medico = Column(Integer, ForeignKey("medico.id_medico"))
    data_consulta = Column(Date, nullable=False)
    horario_consulta = Column(Time, nullable=False)
    status = Column(String(20), default="agendada") 
    observacoes = Column(Text)

    paciente = relationship("Paciente", back_populates="consultas")
    medico = relationship("Medico", back_populates="consultas")

class HorarioDisponivel(Base):
    __tablename__ = "horario_disponivel"

    id_horario = Column(Integer, primary_key=True, index=True)
    id_medico = Column(Integer, ForeignKey("medico.id_medico"))
    data_disponivel = Column(Date, nullable=False)
    horario_inicial = Column(Time, nullable=False)
    horario_final = Column(Time, nullable=False)

    medico = relationship("Medico", back_populates="horarios_disponiveis")

class Admin(Base):
    __tablename__ = "admin"

    id_admin = Column(Integer, primary_key=True, index=True)
    nome_admin = Column(String(100), nullable=False)
    email_admin = Column(String(100), unique=True, nullable=False)
    senha_admin = Column(String(100), nullable=False) 