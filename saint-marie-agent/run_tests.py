import saint_marie_agent
import saint_marie_db
saint_marie_db.init_db()
print('DB initialized')

agent = saint_marie_agent.SaintMarieAgent()

print('=== Chat test 1 ===')
print(agent.chat('Bonjour, pax !'))

print('=== Chat test 2 ===')
print(agent.chat('J aimerais savoir si vous avez des chambres pour le 15 juin au 20 juin pour 2 personnes'))

print('=== Chat test 3 ===')
print(agent.chat('Quels sont les horaires de prière ?'))

print('=== Chat test 4 ===')
print(agent.chat('Comment puis-je vous contacter ?'))

print('=== Booking test ===')
req_id = agent.enregistrer_demandes('Jean Dupont', '15 juin -> 20 juin', 'Retraite', 'Régime vegetarien', '2')
print('Request ID:', req_id)
notif = agent.notifier_hoteliers(req_id)
print('Notification sent:', notif.get('ok', False))

import sqlite3
conn = sqlite3.connect('saint_marie.db')
print('Requests in DB:', conn.execute('SELECT COUNT(*) FROM requests').fetchone()[0])
print('Notifications in DB:', conn.execute('SELECT COUNT(*) FROM notifications').fetchone()[0])
conn.close()
print()
print('All tests passed!')
