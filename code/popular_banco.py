import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import date, time, datetime, timedelta
from random import choice, randint
from faker import Faker
from app import crud  # Adapte o caminho se o crud.py estiver em outro diretório
# Importe os modelos e schemas do seu projeto
from app.models import Paciente, Medico, Consulta, HorarioDisponivel, Admin  # Adapte o caminho conforme necessário
from app.schemas import PacienteCreate, MedicoCreate, ConsultaCreate, HorarioDisponivelCreate, AdminCreate  # Adapte o caminho

# Carregar as variáveis de ambiente do arquivo .env (se aplicável)
from dotenv import load_dotenv
load_dotenv()

# Configuração do banco de dados
DATABASE_URL = os.getenv("DATABASE_URL")  # Obtenha a URL do banco de dados do .env ou defina diretamente
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Gerador de dados falsos
fake = Faker('pt_BR')

# Funções para criar dados falsos
def criar_paciente_falso():
    telefone = fake.phone_number()
    telefone_formatado = ''.join(filter(str.isdigit, telefone))  # Remove caracteres não numéricos
    cpf = fake.cpf()
    cpf_formatado = ''.join(filter(str.isdigit, cpf))  # Remove caracteres não numéricos
    return PacienteCreate(
        nome=fake.name(),
        email=fake.email(),
        telefone=telefone_formatado,
        data_de_nascimento=fake.date_of_birth(),
        cpf=cpf_formatado,
        senha="senha123"  # Substitua por um hash de senha em produção!
    )

def criar_medico_falso():
    especialidades = ["Cardiologia", "Dermatologia", "Pediatria", "Ortopedia", "Neurologia"]
    telefone = fake.phone_number()
    telefone_formatado = ''.join(filter(str.isdigit, telefone))  # Remove caracteres não numéricos
    return MedicoCreate(
        nome=fake.name(),
        email=fake.email(),
        especialidade=choice(especialidades),
        telefone=telefone_formatado,
        crm=fake.numerify("CRM######"),
        senha="senha123"  # Substitua por um hash de senha em produção!
    )

def criar_consulta_falsa(id_paciente, id_medico):
    data_consulta = fake.date_between(start_date="-30d", end_date="+30d")
    horario_consulta = time(randint(8, 17), choice([0, 30]))
    status_opcoes = ["agendada", "confirmada", "em andamento", "finalizada", "cancelada"]
    return ConsultaCreate(
        id_paciente=id_paciente,
        id_medico=id_medico,
        data_consulta=data_consulta,
        horario_consulta=horario_consulta,
        status=choice(status_opcoes),
        observacoes=fake.sentence() if choice([True, False]) else None
    )

def criar_horario_disponivel_falso(id_medico):
    data_disponivel = fake.date_between(start_date="+1d", end_date="+30d")
    horario_inicial = time(randint(8, 17), choice([0, 30]))
    horario_final = (datetime.combine(date.today(), horario_inicial) + timedelta(hours=1)).time()
    return HorarioDisponivelCreate(
        id_medico=id_medico,
        data_disponivel=data_disponivel,
        horario_inicial=horario_inicial,
        horario_final=horario_final
    )

def criar_admin_falso():
    return AdminCreate(
        nome_admin=fake.name(),
        email_admin=fake.email(),
        senha_admin="senha123"  # Substitua por um hash de senha em produção!
    )

# Função principal para popular o banco de dados
def popular_banco_dados(num_pacientes=10, num_medicos=5, num_consultas=20, num_horarios=30, num_admins=2):
    db = SessionLocal()

    # Criar admins
    for _ in range(num_admins):
        admin = criar_admin_falso()
        crud.criar_admin(db, admin)

    # Criar pacientes
    for _ in range(num_pacientes):
        paciente = criar_paciente_falso()
        crud.criar_paciente(db, paciente)

    # Criar médicos
    for _ in range(num_medicos):
        medico = criar_medico_falso()
        crud.criar_medico(db, medico)

    # Criar consultas
    pacientes_ids = db.query(Paciente.id_paciente).all()
    medicos_ids = db.query(Medico.id_medico).all()
    for _ in range(num_consultas):
        id_paciente = choice(pacientes_ids)[0]
        id_medico = choice(medicos_ids)[0]
        consulta = criar_consulta_falsa(id_paciente, id_medico)
        crud.criar_consulta(db, consulta)

    # Criar horários disponíveis
    for _ in range(num_horarios):
        id_medico = choice(medicos_ids)[0]
        horario = criar_horario_disponivel_falso(id_medico)
        crud.criar_horario_disponivel(db, horario)

    db.close()

if __name__ == "__main__":
    popular_banco_dados()
    print("Banco de dados populado com sucesso!") 