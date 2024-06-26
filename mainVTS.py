from bitarray import bitarray

class TsAnalyse:
    def __init__(self):
<<<<<<< HEAD
        self.data = []
        self.packet_size = None
=======
        self.data = None
>>>>>>> 934aed72ca0e297325334988b470a5cb62e89869
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
<<<<<<< HEAD
            raise ValueError("O arquivo não é um TS. Insira um arquivo .ts válido")

        try:
            with open(file_path, 'rb') as file:
                file_data = file.read()
        except IOError:
            raise ValueError("Não foi possível ler o arquivo. Insira um arquivo .ts válido")

        self.packet_size = self.detect_packet_size(file_data)

        if self.packet_size == 188:
            print(f"O arquivo {file_path} é um TS de 188 bytes.")
        elif self.packet_size == 204:
            print(f"O arquivo {file_path} é um BTS de 204 bytes.")
        else:
            raise ValueError("O arquivo não contém pacotes de transporte válidos. Insira um arquivo .ts ou .bts válido")

        sync_byte = b'\x47'
        packets = [file_data[i:i + self.packet_size] for i in range(0, len(file_data), self.packet_size) if file_data[i:i + 1] == sync_byte]

        if not packets:
            raise ValueError(f"O arquivo {file_path} não contém pacotes de transporte válidos. Insira um arquivo .ts válido")

        self.data = packets

    def detect_packet_size(self, file_data):
        sync_byte = b'\x47'
        ts_count = sum(1 for i in range(0, len(file_data) - 188, 188) if file_data[i:i + 1] == sync_byte)
        bts_count = sum(1 for i in range(0, len(file_data) - 204, 204) if file_data[i:i + 1] == sync_byte)
        if ts_count > bts_count:
            return 188
        else:
            return 204

    def analise_pat(self):
        pat = []
        for packet in self.data:
            pid = ((packet[1] & 0x1F) << 8) | packet[2]
            if pid == 0x0000:
                pointer_field = packet[4]
                table_id = packet[5 + pointer_field]
                if table_id == 0x00:  # PAT
                    section_length = ((packet[6 + pointer_field] & 0x0F) << 8) | packet[7 + pointer_field]
                    section_data = packet[5 + pointer_field: 5 + pointer_field + 3 + section_length]
                    pat.append(section_data)
        self.tables['PAT'] = pat

    def analise_pmt(self):
        pmt = []
        pat_packets = self.tables['PAT']
        pmt_pids = []
        for pat_packet in pat_packets:
            section_length = ((pat_packet[1] & 0x0F) << 8) | pat_packet[2]
            program_info_start = 8
            program_info_end = 3 + section_length - 4  # minus 4 for CRC
            while program_info_start < program_info_end:
                program_number = (pat_packet[program_info_start] << 8) | pat_packet[program_info_start + 1]
                program_info_start += 2
                if program_number != 0x0000:
                    pmt_pid = ((pat_packet[program_info_start] & 0x1F) << 8) | pat_packet[program_info_start + 1]
                    pmt_pids.append(pmt_pid)
                program_info_start += 2

        for packet in self.data:
            pid = ((packet[1] & 0x1F) << 8) | packet[2]
            if pid in pmt_pids:
                pointer_field = packet[4]
                table_id = packet[5 + pointer_field]
                if table_id == 0x02:  # PMT
                    section_length = ((packet[6 + pointer_field] & 0x0F) << 8) | packet[7 + pointer_field]
                    section_data = packet[5 + pointer_field: 5 + pointer_field + 3 + section_length]
                    pmt.append(section_data)
        self.tables['PMT'] = pmt

    def analise_cat(self):
        cat = []
        for packet in self.data:
            pid = ((packet[1] & 0x1F) << 8) | packet[2]
            if pid == 0x0001:
                pointer_field = packet[4]
                table_id = packet[5 + pointer_field]
                if table_id == 0x01:  # CAT
                    section_length = ((packet[6 + pointer_field] & 0x0F) << 8) | packet[7 + pointer_field]
                    section_data = packet[5 + pointer_field: 5 + pointer_field + 3 + section_length]
                    cat.append(section_data)
        self.tables['CAT'] = cat

    def analise_eit(self):
        eit = []
        for packet in self.data:
            pid = ((packet[1] & 0x1F) << 8) | packet[2]
            if pid in [0x0012, 0x0026, 0x0027]:  # EIT PIDs
                pointer_field = packet[4]
                if 5 + pointer_field < len(packet):
                    table_id = packet[5 + pointer_field]
                    if table_id in range(0x4E, 0x70):  # EIT table_ids
                        section_length = ((packet[6 + pointer_field] & 0x0F) << 8) | packet[7 + pointer_field]
                        section_data = packet[5 + pointer_field: 5 + pointer_field + 3 + section_length]
                        eit.append(section_data)
        self.tables['EIT'] = eit

    def analise_nit(self):
        nit = []
        for packet in self.data:
            pid = ((packet[1] & 0x1F) << 8) | packet[2]
            if pid == 0x0010:
                pointer_field = packet[4]
                table_id = packet[5 + pointer_field]
                if table_id in [0x40, 0x41]:  # NIT (actual and other network)
                    section_length = ((packet[6 + pointer_field] & 0x0F) << 8) | packet[7 + pointer_field]
                    section_data = packet[5 + pointer_field: 5 + pointer_field + 3 + section_length]
                    nit.append(section_data)
        self.tables['NIT'] = nit

    def analise_sdt(self):
        sdt = []
        for packet in self.data:
            pid = ((packet[1] & 0x1F) << 8) | packet[2]
            if pid == 0x0011:
                pointer_field = packet[4]
                table_id = packet[5 + pointer_field]
                if table_id in [0x42, 0x46]:  # SDT (actual and other transport stream)
                    section_length = ((packet[6 + pointer_field] & 0x0F) << 8) | packet[7 + pointer_field]
                    section_data = packet[5 + pointer_field: 5 + pointer_field + 3 + section_length]
                    sdt.append(section_data)
        self.tables['SDT'] = sdt

=======
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

>>>>>>> 934aed72ca0e297325334988b470a5cb62e89869
    def get_table_data(self):
        table_data = {}
        for table in self.tables:
            table_data[table] = []
            for packet in self.tables[table]:
<<<<<<< HEAD
                if isinstance(packet, (bytes, bytearray)):
                    header = packet[:4]
                    payload = packet[4:]
                    table_data[table].append({
                        'header': header,
                        'payload': payload
                    })
                else:
                    print(f"Warning: packet in table {table} is not a valid bytes object.")
=======
                header = packet[:4]
                payload = packet[4:]
                table_data[table].append({
                    'header': header,
                    'payload': payload
                })
>>>>>>> 934aed72ca0e297325334988b470a5cb62e89869
        self.table_data = table_data

    def validate_ts_file(self):
        required_tables = ['PAT', 'CAT', 'PMT', 'NIT', 'SDT', 'EIT']
        for table in required_tables:
            if not self.tables[table]:
<<<<<<< HEAD
                print(f"Tabela {table} não encontrada ou inválida.")
=======
                print(f"Tabela {table} não encontrada ou invalida.")
>>>>>>> 934aed72ca0e297325334988b470a5cb62e89869
                return False
        print("Todas as tabelas obrigatórias estão presentes e são válidas.")
        return True

    def print_table_data(self):
        for table, data in self.table_data.items():
            print(f"Data for {table}:")
            for entry in data:
                print(f"Header: {entry['header']}")
                print(f"Payload: {entry['payload']}")

<<<<<<< HEAD

# Exemplo de uso:
ts_analyse = TsAnalyse()
try:
    #ts_analyse.read_ts_file('C:/Users/kacia/OneDrive/Documentos/TVcultura.ts')
    #ts_analyse.read_ts_file('C:/Users/kacia/OneDrive/Documentos/super.png')
    #ts_analyse.read_ts_file('C:/Users/kacia/OneDrive/Documentos/Aquarioepg.ts')
    ts_analyse.read_ts_file('C:/Users/kacia/OneDrive/Documentos/redeamazonica.ts')
    ts_analyse.analise_pat()
    ts_analyse.analise_cat()
    ts_analyse.analise_pmt()
    ts_analyse.analise_nit()
    ts_analyse.analise_sdt()
    ts_analyse.analise_eit()
=======
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
>>>>>>> 934aed72ca0e297325334988b470a5cb62e89869
    ts_analyse.get_table_data()
    ts_analyse.validate_ts_file()
    # Para imprimir os dados de header e payload das tabelas, use o método abaixo:
    # ts_analyse.print_table_data()
except ValueError as e:
    print(e)

