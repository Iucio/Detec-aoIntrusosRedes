Sistema de Detecção de Intrusos em Redes com Machine Learning

 Descrição do Projeto

Este projeto consiste na implementação de um sistema de detecção de intrusos para redes, utilizando conceitos de Machine Learning e a linguagem Python. O objetivo principal é demonstrar, de forma prática, como o tráfego de rede pode ser analisado para identificar padrões anormais ou comportamentos maliciosos, característicos de ataques cibernéticos como DDoS (Distributed Denial of Service), varredura de portas, e outras intrusões.

A aplicação funciona capturando pacotes de rede em tempo real através da biblioteca Scapy. As informações extraídas desses pacotes (como tamanho, protocolo, portas, flags TCP, etc.) são então processadas e alimentam um modelo de Machine Learning (baseado em algoritmos de classificação como Random Forest) previamente treinado com o dataset NSL-KDD, que contém exemplos de atividades normais e de ataque.

O sistema não apenas detecta potenciais intrusões, mas também oferece uma interface visual intuitiva desenvolvida com Streamlit, que permite a apresentação em tempo real do desempenho da rede, exibindo alertas de segurança e métricas relevantes do tráfego. Este laboratório didático serve como uma ferramenta para explorar e compreender conceitos fundamentais de redes, segurança cibernética, e a aplicação prática de inteligência artificial na proteção de infraestruturas.


 Tópicos da Disciplina Abordados

Este projeto de aplicação aborda diversos tópicos estudados na disciplina de Redes, incluindo:

* Medição de desempenho de rede: Indiretamente, através da contagem e categorização de pacotes em tempo real.
* Utilização de sockets: Fundamental para a captura de pacotes brutos realizada pela biblioteca Scapy.
* Utilização de Threads: Essencial para permitir que a captura de pacotes ocorra em segundo plano sem bloquear a interface de usuário do Streamlit.
* Um dashboard para apresentação em tempo real do desempenho de rede: Implementado com a biblioteca Streamlit.
* TCP/IP: Análise das camadas de rede (IP, TCP, UDP, ICMP), flags TCP e protocolos para extração de features.
* Roteamento: Análise de endereços IP de origem e destino dos pacotes.
* Difusão/Host: Na interpretação de algumas features de taxa e contagem baseadas em hosts e serviços.
* Conceitos de Machine Learning aplicados à segurança de redes: Treinamento de modelo para classificação de tráfego (Normal vs. Ataque).


 Pré-requisitos

Para rodar este projeto, você precisará ter instalado:

Python (versão 3.8 ou superior é recomendada).
Npcap: Para sistemas Windows, o Npcap é essencial para a captura de pacotes. Baixe e instale-o do (https://nmap.org/npcap/). 
Git: Para clonar o repositório.

As bibliotecas Python necessárias são listadas no arquivo `requirements.txt` deste repositório.

---

 Instruções de Instalação

Siga os passos abaixo para configurar e instalar o projeto:

1.  Clone o Repositório:
    Abra seu terminal (preferencialmente **MINGW64/Git Bash**) e clone o projeto:
    ```bash
    git clone https://github.com/Iucio/Detec-aoIntrusosRedes.git
    cd Detec-aoIntrusosRedes
    ```
    

2.  Crie e Ative o Ambiente Virtual:
    É altamente recomendado usar um ambiente virtual para isolar as dependências do projeto:
    ```bash
    python -m venv venv
    source venv/Scripts/activate # No Windows, usando MINGW64/Git Bash
    # ou venv\Scripts\activate # No Windows, usando Prompt de Comando/PowerShell
    ```

3.  Instale as Dependências Python:
    Com o ambiente virtual ativo, instale todas as bibliotecas necessárias:
    ```bash
    pip install -r requirements.txt
    ```

4.  Baixe o Dataset NSL-KDD:
    Este projeto utiliza o dataset NSL-KDD para treinamento do modelo de Machine Learning.
    * Baixe os arquivos `KDDTrain+.txt` e `KDDTest+.txt` do [Kaggle NSL-KDD Dataset](https://www.kaggle.com/datasets/goyalshalini92/nslkdd).
    * Crie uma pasta chamada `data/` na raiz do seu projeto (ao lado das pastas `venv/`, `models/`, etc.).
    * Mova os arquivos `KDDTrain+.txt` e `KDDTest+.txt` baixados para a pasta `data/`.

---

 Instruções de Uso

Siga estas instruções para treinar o modelo, rodar o dashboard e simular ataques:

1.  Treinamento do Modelo de Machine Learning:
    O modelo precisa ser treinado uma única vez.
     Abra o VS Code e abra a pasta do projeto 
     Abra o arquivo `01_EDA_NSLKDD.ipynb`.
     No canto superior direito do notebook, selecione o kernel Python do seu ambiente virtual (`(venv)`).
    * Execute todas as células do notebook em ordem. Isso irá carregar os dados, pré-processá-los, treinar o modelo e salvá-lo (junto com o scaler e a lista de features) na pasta `models/`.
        *(Opcional: Verifique se os arquivos `random_forest_model.pkl`, `scaler.pkl` e `feature_columns.pkl` foram criados na pasta `models/`.)

2.  Executar o Dashboard de Detecção de Intrusos (IDS):
    Este passo iniciará a aplicação web do IDS.
     Abra um terminal COMO ADMINISTRADOR. (Isso é crucial para que o Scapy possa capturar pacotes).
     Navegue até a raiz do seu projeto 
     Ative o ambiente virtual: ‘source venv/Scripts/activate’
     Execute o Streamlit:
        streamlit run app.py
     Seu navegador padrão abrirá uma nova aba com o dashboard do IDS.

3.  Simular Ataques (para Demonstração):
    Com o dashboard do IDS rodando no navegador, você pode simular ataques para testar a detecção.
     Abra outro terminal separado (também como admnistrador)
     Navegue até a raiz do seu projeto 
    *Ative o ambiente virtual: ‘source venv/Scripts/activate’
     Execute o script de simulação:
        python simulate_attack.py

     Observe o dashboard: Os contadores de "Pacotes de Ataque" devem aumentar, e os alertas detalhados devem aparecer na tabela "Alertas de Intrusão Recentes".
     Você pode executar `python simulate_attack.py` várias vezes seguidas para gerar mais volume de ataques para a demonstração.
    Gere também tráfego de navegação normal para ver o contador de "Pacotes Normais" aumentando.

4. Parar o Monitoramento:
    No dashboard do Streamlit no navegador, clique no botão "Parar Monitoramento" para encerrar a captura de pacotes.


Autoria e Contribuições

Este projeto foi desenvolvido por:

Carlos Henrique Nascimento –  Responsável pela pesquisa e organização do dataset (NSL – KDD)
Desenvolvimento do notebook “01_EDA_NSLKDD_IPYNB”,  incluindo carregamento de dados, treinamento do modelo de machine learning e avaliação de seu desempenho

André Meschesi Dantas – Aprofundamento na biblioteca Scapy para captura e analise dos pacotes.
Desenvolvimento do “packet_processor.py”, focado na extração de características do pacote em tempo real.
Implementação de heurísticas para detecção de ataques simulados e debugging de problemas de captura.
 
Vinicius Araujo de Oliveira – Responsável pela implementação da interface utilizando Streamlit
Criação do dashboard e seu layout (gráfico, tabela de alerta etc)
Integração de “ml_utils.py” e “packet_processor.py” na aplicação. 


Lucio Diniz Araujo Martelo Junior - Gerenciamento do projeto (configuração inicial do ambiente Git/GitHub, divisão de tarefas, acompanhamento).
Desenvolvimento do script `simulate_attack.py` para simulação de ataques. 
Elaboração da documentação no `README.md` e preparação para a apresentação em vídeo.
