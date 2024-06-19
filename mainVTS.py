from bitarray import bitarray

class TsAnalyse:
    def __init__(self):
        self.data = None
        self.tables = {
            'PAT': [],
            'CAT': [],
            'PMT': [],
            'NIT': [],
            'SDT': [],
            'EIT': []
        }

    def read_ts_file(self, file_path):
        if not file_path.endswith('.ts'):
            raise ValueError("O arquivo não é um TS insira um arquivo .ts")

        try:
            with open(file_path, 'rb') as file:
                self.data = file.read()
        except IOError:
            raise ValueError("Não foi possível ler o arquivo. Insira um arquivo .ts válido")

        sync_byte = b'\x47'
        packets = [self.data[i:i + 188] for i in range(0, len(self.data), 188) if self.data[i:i + 1] == sync_byte]

        if not packets:
            raise ValueError("O arquivo não contém pacotes de transporte válidos. Insira um arquivo .ts válido")

        self.data = packets

    def parse_pat(self):
        pat = []
        for packet in self.data:
            if packet[1] == 0x00:
                pat.append(packet)
        self.tables['PAT'] = pat

    def parse_cat(self):
        cat = []
        for packet in self.data:
            if packet[1] == 0x01:
                cat.append(packet)
        self.tables['CAT'] = cat

    def parse_pmt(self):
        pmt = []
        for packet in self.data:
            if packet[1] == 0x02:
                pmt.append(packet)
        self.tables['PMT'] = pmt

    def parse_nit(self):
        nit = []
        for packet in self.data:
            if packet[1] == 0x40 or packet[1] == 0x41:
                nit.append(packet)
        self.tables['NIT'] = nit

    def parse_sdt(self):
        sdt = []
        for packet in self.data:
            if packet[1] == 0x42 or packet[1] == 0x46:
                sdt.append(packet)
        self.tables['SDT'] = sdt

    def parse_eit(self):
        eit = []
        for packet in self.data:
            if packet[1] in range(0x4E, 0x6F + 1):
                eit.append(packet)
        self.tables['EIT'] = eit

    def get_table_data(self):
        table_data = {}
        for table in self.tables:
            table_data[table] = []
            for packet in self.tables[table]:
                header = packet[:4]
                payload = packet[4:]
                table_data[table].append({
                    'header': header,
                    'payload': payload
                })
        self.table_data = table_data

    def validate_ts_file(self):
        required_tables = ['PAT', 'CAT', 'PMT', 'NIT', 'SDT', 'EIT']
        for table in required_tables:
            if not self.tables[table]:
                print(f"Tabela {table} não encontrada ou invalida.")
                return False
        print("Todas as tabelas obrigatórias estão presentes e são válidas.")
        return True

    def print_table_data(self):
        for table, data in self.table_data.items():
            print(f"Data for {table}:")
            for entry in data:
                print(f"Header: {entry['header']}")
                print(f"Payload: {entry['payload']}")

# Exemplo de uso:
ts_analyse = TsAnalyse()
try:
    #ts_analyse.read_ts_file('C:/Users/kacia/OneDrive/Documentos/redeamazonica.ts')
    #ts_analyse.read_ts_file('C:/Users/kacia/OneDrive/Documentos/super.png')
    ts_analyse.read_ts_file('C:/Users/kacia/OneDrive/Documentos/Aquarioepg.ts')
    ts_analyse.parse_pat()
    ts_analyse.parse_cat()
    ts_analyse.parse_pmt()
    ts_analyse.parse_nit()
    ts_analyse.parse_sdt()
    ts_analyse.parse_eit()
    ts_analyse.get_table_data()
    ts_analyse.validate_ts_file()
    # Para imprimir os dados de header e payload das tabelas, use o método abaixo:
    # ts_analyse.print_table_data()
except ValueError as e:
    print(e)

