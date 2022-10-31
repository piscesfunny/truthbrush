from truthbrush.api import TruthSocialClient

if __name__ == '__main__':
    api = TruthSocialClient()
    items = api.home()
    print(items)
