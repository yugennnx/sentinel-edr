import multiprocessing
import time
import sys
from database import db_writer_worker
from sensors import physical_layer_worker, cyber_layer_worker, network_layer_worker, local_behavior_worker
from ai_engine import ai_fusion_worker 

def message_router(main_q, db_q, ai_q):
    while True:
        try:
            item = main_q.get()
            if item == "STOP":
                db_q.put("STOP")
                ai_q.put("STOP")
                break
            db_q.put(item)
            ai_q.put(item)
        except Exception:
            pass

def main():
    print("[*] SENTINEL Baslatiliyor...")
    
    sensor_queue = multiprocessing.Queue() 
    db_queue = multiprocessing.Queue()     
    ai_queue = multiprocessing.Queue()     

    phys_process = multiprocessing.Process(target=physical_layer_worker, args=(sensor_queue,))
    cyber_process = multiprocessing.Process(target=cyber_layer_worker, args=(sensor_queue,))
    net_process = multiprocessing.Process(target=network_layer_worker, args=(sensor_queue,))
    
    # YENİ EKLENEN LOKAL DAVRANIŞ SENSÖRÜ
    local_process = multiprocessing.Process(target=local_behavior_worker, args=(sensor_queue,))
    
    db_process = multiprocessing.Process(target=db_writer_worker, args=(db_queue,))
    ai_process = multiprocessing.Process(target=ai_fusion_worker, args=(ai_queue,)) 
    
    router_process = multiprocessing.Process(target=message_router, args=(sensor_queue, db_queue, ai_queue))

    router_process.start()
    db_process.start()
    phys_process.start()
    cyber_process.start()
    net_process.start()
    local_process.start() # Lokal sensörü ateşle
    ai_process.start() 
    
    print("[+] Tum cekirdek moduller devrede (Fiziksel, Siber, Ag, Lokal, AI, Router). Veri isleniyor...")
    print("[!] Cikis yapmak icin konsolda Ctrl+C'ye basin.")

    try:
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[!] Kapatilma sinyali alindi. Sistem guvenli moda geciyor...")
        
        phys_process.terminate()
        cyber_process.terminate()
        net_process.terminate()
        local_process.terminate() # Kapanışta lokal sensörü durdur
        ai_process.terminate()
        router_process.terminate()
        
        sensor_queue.put("STOP")
        
        phys_process.join()
        cyber_process.join()
        net_process.join()
        local_process.join()
        ai_process.join()
        db_process.join()
        router_process.join()
        
        print("[-] SENTINEL guvenle kapatildi.")
        sys.exit(0)

if __name__ == '__main__':
    multiprocessing.freeze_support()
    main()