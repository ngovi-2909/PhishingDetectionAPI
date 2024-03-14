import pandas as pd
import whois
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import MinMaxScaler
from train_model.features import *

scaler = MinMaxScaler()
data = pd.read_csv('train_model/data.csv')
data['status'] = data['status'].map({'phishing': 1, 'legitimate': 0})

# Split data into X and y
X = data.drop(['url', 'status'], axis=1).values
y = data['status'].values

# scale data
scaler.fit(X)
# start scale
X = scaler.transform(X)


def create_vector(url):
    key = "wgowgcc4s4os0os8skw4wckw88s8wwkccwcsgcgg"
    flag = 1
    features = []
    response = ""
    content = ""
    text = ""
    soup = ""
    try:
        response = requests.get(url, timeout=5)
        content = response.content
        text = response.text
        soup = BeautifulSoup(response.text, 'html.parser')
    except:
        response = ""
        content = ""
        text = ""
        soup = ""

    try:
        domain_name = whois(urlparse(url).netloc)
    except:
        flag = 0
    features.append(is_ip(url)),

    features.append(length_url(url)),
    features.append(length_hostname(url)),

    features.append(tiny_url(url)),
    features.append(countAtSign(url)),

    features.append(countQuestionMark(url)),
    features.append(countHyphen(url)),

    features.append(countDot(url)),
    features.append(countComma(url)),

    features.append(countSemicolon(url)),
    features.append(countDollar(url)),

    features.append(countSlash(url)),
    features.append(have_redirect(url)),

    features.append(CountEqual(url)),
    features.append(CountPercent(url)),

    features.append(CountUnderScore(url)),
    features.append(CountDotHostName(url)),

    features.append(CountColon(url)),
    features.append(CountStar(url)),

    features.append(CountHttp(url)),
    features.append(check_https_protocol(url)),

    features.append(RatioDigitsInHostname(url)),
    features.append(RatioDigitsURL(url)),

    features.append(have_prefixOrSuffix(url)),
    features.append(dns_expiration(url)),

    features.append(web_forwarding(response)),
    features.append(page_rank(key, url)),

    features.append(0 if flag == 0 else DomainAge(domain_name)),
    features.append(0 if flag == 0 else DomainRegLen(domain_name)),
    features.append(LinksInScriptTags(soup, url)),
    features.append(AnchorURL(soup, url)),
    features.append(popup_window(content)),
    features.append(abnormal_subdomain(url)),
    features.append(iframe(text)),

    features.append(count_www_path(url)),
    features.append(count_com_path(url)),
    features.append(length_word_raw(url)),

    features.append(average_word_length(raw_words(url))),
    features.append(average_word_length(raw_words_host(url))),
    features.append(average_word_length(raw_words_path(url))),

    features.append(longest_word_length(raw_words(url))),
    features.append(longest_word_length(raw_words_host(url))),
    features.append(longest_word_length(raw_words_path(url))),

    features.append(shortest_word_length(raw_words(url))),
    features.append(shortest_word_length(raw_words_host(url))),
    features.append(shortest_word_length(raw_words_path(url))),
    features.append(web_traffic(url)),
    features.append(whois_registered_domain(url))

    return features


def get_columns():
    return [
        'is_ip',
        'length_url',
        'length_hostname',
        'tiny_url',
        'CountAtSign',
        'CountQuestionMark',
        'CountHyphen',
        'CountDot',
        'CountComma',
        'CountSemicolon',
        'CountDollar',
        'CountSlash',
        'have_redirect',
        'CountEqual',
        'CountPercent',
        'CountUnderScore',
        'CountDotHostName',
        'CountColon',
        'CountStar',
        'CountHttp',
        'checkHttps',
        'RatioDigitHost',
        'RatioDigitsURL',
        'have_prefixOrSuffix',
        'dns_expiration',
        'Count_redirect',
        'page_rank',
        'domain_age',
        'domainRegLen',
        'RatioLinksTag',
        'RatioAnchorURL',
        'poppup_window',
        'abnormal_subdomain',
        'iframe',
        'Count_www_path',
        'Count_com_path',
        'length_word_raw',
        'avg_row_words',
        'avg_row_words_host',
        'avg_row_words_path',
        'longest_words_raw',
        'longest_word_host',
        'longest_word_path',
        'shortest_words_raw',
        'shortest_word_host',
        'shortest_word_path',
        'webTraffic',
        'whoisRegistered',
    ]


def train_data():
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=0)
    randomForest = RandomForestClassifier()
    model_rf = randomForest.fit(X_train, y_train)
    return model_rf


def predict(model, url):
    df = pd.DataFrame([create_vector(url)], columns=get_columns())
    traffic = df['webTraffic'].iloc[0]
    age = df['domain_age'].iloc[0]
    regLen = df['domainRegLen'].iloc[0]
    pageRank = df['page_rank'].iloc[0]
    df = scaler.transform(df)
    rf_predict = model.predict(df)

    result = {'web_traffic': traffic,
              'domain_age': age,
              'domain_register_length': regLen,
              'page_rank': pageRank,
              'result': rf_predict.tolist()[0]
              }
    return result

#
# def main():
#     url = input('Enter url: ')
#     print(predict(url))
#
#
# if __name__ == '__main__':
#     main()
